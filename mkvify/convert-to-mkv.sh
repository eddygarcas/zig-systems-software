#!/usr/bin/env bash
# convert-to-mkv.sh — batch-convert videos to smart-TV-friendly MKV.
#
# Probes each file and copies streams that are already TV-safe (instant,
# lossless), transcoding only what isn't. Re-encoding never improves quality,
# so the script avoids it wherever possible.

set -uo pipefail

VERSION="2.0"
PROG="${0##*/}"

# --- defaults ---------------------------------------------------------------
ENCODER=libx264
CRF=20
OUTDIR=mkv
VAAPI_DEVICE=/dev/dri/renderD128
DUALTRACK=0
NORMALIZE=0
ABR=192k
ABR_MULTI=384k
RECURSIVE=0
OVERWRITE=0
DRYRUN=0
NO_HEVC=0
QUIET=0

AUDIO_OK_REGEX='^(aac|ac3|eac3|mp3)$'
EXTS=(mp4 avi mov wmv flv mpg mpeg m4v ts webm divx vob 3gp mkv)

usage() {
cat << 'EOF'
convert-to-mkv — batch-convert videos to smart-TV-friendly MKV

USAGE
  convert-to-mkv [OPTIONS] [FILE|DIR ...]

  With no FILE or DIR, the current directory is used. Directories are scanned
  for known video extensions; files are taken as given.

VIDEO OPTIONS
  -e, --encoder ENC        libx264 | h264_nvenc | h264_vaapi   (default: libx264)
                           Use the GPU encoders for speed, libx264 for the best
                           quality per bitrate.
  -q, --crf N              Video quality, lower is better, sane range 18-23
                           (default: 20). Only applies when re-encoding.
      --no-hevc            Treat H.265/HEVC as NOT TV-safe and re-encode it to
                           H.264. Use this for older TVs.
      --vaapi-device PATH  VAAPI render node (default: /dev/dri/renderD128)

AUDIO OPTIONS
  -d, --dual-track         Keep the original audio untouched AND add a TV-safe
                           AAC stereo track beside it, flagged as default. No
                           quality loss; the TV picks the compatible track.
  -n, --normalize          EBU R128 loudness normalisation plus a dialogue-
                           forward downmix. Makes speech audible on TV speakers.
                           Forces an audio re-encode.
  -b, --audio-bitrate BR   Bitrate for encoded stereo tracks (default: 192k)
  -B, --multi-bitrate BR   Bitrate when keeping multichannel (default: 384k)

OUTPUT OPTIONS
  -o, --outdir DIR         Output directory (default: mkv)
  -r, --recursive          Scan directories recursively
  -y, --overwrite          Overwrite existing output files instead of skipping
      --dry-run            Show what would be done, convert nothing
  -Q, --quiet              Suppress ffmpeg progress output

  -h, --help               Show this help
  -V, --version            Show version

EXAMPLES
  # Sensible default for a smart TV, using an NVIDIA GPU
  convert-to-mkv -e h264_nvenc -d -n ~/Videos

  # Old TV that can't do H.265, recurse through subfolders
  convert-to-mkv --no-hevc -r -o /mnt/media/tv ~/Videos

  # See what would happen without touching anything
  convert-to-mkv --dry-run *.avi

NOTES
  MKV is only a container: rewrapping is instant and lossless. Audio or video
  is re-encoded only when a codec would not play on the TV. Re-encoding cannot
  add quality, so -d is preferred over replacing the original audio.
EOF
}

die() { echo "$PROG: $*" >&2; echo "Try '$PROG --help' for more information." >&2; exit 2; }
need_arg() { [[ -n "${2:-}" ]] || die "option '$1' requires an argument"; }

# --- argument parsing -------------------------------------------------------
TARGETS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -e|--encoder)        need_arg "$1" "${2:-}"; ENCODER="$2"; shift 2 ;;
    -q|--crf)            need_arg "$1" "${2:-}"; CRF="$2"; shift 2 ;;
    -o|--outdir)         need_arg "$1" "${2:-}"; OUTDIR="$2"; shift 2 ;;
    -b|--audio-bitrate)  need_arg "$1" "${2:-}"; ABR="$2"; shift 2 ;;
    -B|--multi-bitrate)  need_arg "$1" "${2:-}"; ABR_MULTI="$2"; shift 2 ;;
    --vaapi-device)      need_arg "$1" "${2:-}"; VAAPI_DEVICE="$2"; shift 2 ;;
    -d|--dual-track)     DUALTRACK=1; shift ;;
    -n|--normalize|--normalise) NORMALIZE=1; shift ;;
    --no-hevc)           NO_HEVC=1; shift ;;
    -r|--recursive)      RECURSIVE=1; shift ;;
    -y|--overwrite)      OVERWRITE=1; shift ;;
    --dry-run)           DRYRUN=1; shift ;;
    -Q|--quiet)          QUIET=1; shift ;;
    -h|--help)           usage; exit 0 ;;
    -V|--version)        echo "convert-to-mkv $VERSION"; exit 0 ;;
    --)                  shift; TARGETS+=("$@"); break ;;
    -*)                  die "unknown option '$1'" ;;
    *)                   TARGETS+=("$1"); shift ;;
  esac
done

[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=(.)

# --- validation -------------------------------------------------------------
case "$ENCODER" in
  libx264|h264_nvenc|h264_vaapi) ;;
  *) die "invalid encoder '$ENCODER' (expected libx264, h264_nvenc or h264_vaapi)" ;;
esac
[[ "$CRF" =~ ^[0-9]+$ ]] || die "--crf must be a number, got '$CRF'"
command -v ffmpeg  >/dev/null || die "ffmpeg not found (sudo pacman -S ffmpeg)"
command -v ffprobe >/dev/null || die "ffprobe not found (sudo pacman -S ffmpeg)"
[[ "$ENCODER" == h264_vaapi && ! -e "$VAAPI_DEVICE" ]] \
  && die "VAAPI device '$VAAPI_DEVICE' not found"
for t in "${TARGETS[@]}"; do
  [[ -e "$t" ]] || die "no such file or directory: $t"
done

if [[ "$NO_HEVC" == 1 ]]; then VIDEO_OK_REGEX='^h264$'; else VIDEO_OK_REGEX='^(h264|hevc)$'; fi
[[ "$DRYRUN" == 0 ]] && mkdir -p "$OUTDIR"
outdir_abs=$(cd "$OUTDIR" 2>/dev/null && pwd || echo "")

DOWNMIX='pan=stereo|FL=0.5*FC+0.707*FL+0.5*BL+0.5*SL|FR=0.5*FC+0.707*FR+0.5*BR+0.5*SR'
LOUDNORM='loudnorm=I=-16:TP=-1.5:LRA=11'
LOGLEVEL=(-hide_banner -loglevel warning -stats)
[[ "$QUIET" == 1 ]] && LOGLEVEL=(-hide_banner -loglevel error)

# --- gather input files -----------------------------------------------------
collect() {
  local target="$1"
  if [[ -f "$target" ]]; then printf '%s\0' "$target"; return; fi
  local depth=() expr=() e
  [[ "$RECURSIVE" == 0 ]] && depth=(-maxdepth 1)
  for e in "${EXTS[@]}"; do expr+=(-iname "*.$e" -o); done
  unset 'expr[${#expr[@]}-1]'
  find "$target" "${depth[@]}" -type f \( "${expr[@]}" \) -print0 2>/dev/null
}

files=()
for t in "${TARGETS[@]}"; do
  while IFS= read -r -d '' file; do files+=("$file"); done < <(collect "$t")
done

[[ ${#files[@]} -eq 0 ]] && { echo "$PROG: no video files found"; exit 0; }

converted=0 skipped=0 failed=0

for f in "${files[@]}"; do
  # never re-process our own output
  fdir=$(cd "$(dirname "$f")" && pwd)
  [[ -n "$outdir_abs" && "$fdir" == "$outdir_abs" ]] && continue

  base=$(basename "$f"); base="${base%.*}"
  out="$OUTDIR/$base.mkv"

  if [[ -e "$out" && "$OVERWRITE" == 0 ]]; then
    echo "skip (exists): $out"; ((skipped++)); continue
  fi

  vcodec=$(ffprobe -v error -select_streams v:0 -show_entries stream=codec_name \
             -of default=nw=1:nk=1 "$f" 2>/dev/null | head -n1)
  acodec=$(ffprobe -v error -select_streams a:0 -show_entries stream=codec_name \
             -of default=nw=1:nk=1 "$f" 2>/dev/null | head -n1)
  achans=$(ffprobe -v error -select_streams a:0 -show_entries stream=channels \
             -of default=nw=1:nk=1 "$f" 2>/dev/null | head -n1)
  naudio=$(ffprobe -v error -select_streams a -show_entries stream=index \
             -of default=nw=1:nk=1 "$f" 2>/dev/null | wc -l)
  achans="${achans:-2}"

  # --- video ---
  vpre=()
  if [[ "$vcodec" =~ $VIDEO_OK_REGEX ]]; then
    vargs=(-c:v copy)
  else
    case "$ENCODER" in
      libx264)    vargs=(-c:v libx264 -crf "$CRF" -preset medium) ;;
      h264_nvenc) vargs=(-c:v h264_nvenc -cq "$CRF" -preset p5) ;;
      h264_vaapi) vpre=(-vaapi_device "$VAAPI_DEVICE")
                  vargs=(-vf format=nv12,hwupload -c:v h264_vaapi -qp "$CRF") ;;
    esac
  fi

  # --- audio ---
  audio_ok=0
  [[ "$acodec" =~ $AUDIO_OK_REGEX ]] && audio_ok=1
  maps=(-map 0); aargs=(); note=""

  # Dual-track applies whenever the original would otherwise be altered:
  # an incompatible codec, or a requested normalisation. The original is
  # always preserved bit-for-bit and the new track carries the processing.
  if [[ "$DUALTRACK" == 1 && ( "$audio_ok" == 0 || "$NORMALIZE" == 1 ) ]]; then
    maps+=(-map 0:a:0)
    aargs=(-c:a copy
           -c:a:"$naudio" aac -b:a:"$naudio" "$ABR" -ac:"$naudio" 2
           -metadata:s:a:"$naudio" title="Stereo AAC (TV)"
           -disposition:a:0 0 -disposition:a:"$naudio" default)
    filters=()
    [[ "$achans" -gt 2 ]] && filters+=("$DOWNMIX")
    [[ "$NORMALIZE" == 1 ]] && filters+=("$LOUDNORM")
    if [[ ${#filters[@]} -gt 0 ]]; then
      IFS=, ; aargs+=(-filter:a:"$naudio" "${filters[*]}") ; unset IFS
    fi
    note="original kept + AAC stereo added"
    [[ "$NORMALIZE" == 1 ]] && note="$note (normalised)"
  elif [[ "$audio_ok" == 1 && "$NORMALIZE" == 0 ]]; then
    aargs=(-c:a copy); note="audio copied"
  else
    filters=()
    [[ "$achans" -gt 2 && ( "$DUALTRACK" == 1 || "$NORMALIZE" == 1 ) ]] && filters+=("$DOWNMIX")
    [[ "$NORMALIZE" == 1 ]] && filters+=("$LOUDNORM")
    if [[ "$achans" -gt 2 && ${#filters[@]} -eq 0 ]]; then
      aargs=(-c:a aac -b:a "$ABR_MULTI")
    else
      aargs=(-c:a aac -b:a "$ABR")
    fi
    if [[ ${#filters[@]} -gt 0 ]]; then
      IFS=, ; aargs+=(-af "${filters[*]}") ; unset IFS
      aargs+=(-ac 2)
    fi
    note="audio re-encoded"
    [[ "$NORMALIZE" == 1 ]] && note="$note + normalised"
  fi

  echo "==> $f  [v:${vcodec:-none} a:${acodec:-none} ${achans}ch]  ($note)"

  if [[ "$DRYRUN" == 1 ]]; then
    echo "    would run: ffmpeg ${vpre[*]} -i '$f' ${maps[*]} ${vargs[*]} ${aargs[*]} -c:s copy '$out'"
    continue
  fi

  if ffmpeg "${LOGLEVEL[@]}" -y "${vpre[@]}" -i "$f" \
       "${maps[@]}" "${vargs[@]}" "${aargs[@]}" -c:s copy "$out"; then
    echo "    done"; ((converted++))
  else
    echo "    subtitle copy failed, retrying without subtitles"
    rm -f "$out"
    if ffmpeg "${LOGLEVEL[@]}" -y "${vpre[@]}" -i "$f" \
         -map 0:v -map '0:a?' "${vargs[@]}" "${aargs[@]}" "$out"; then
      echo "    done (no subs)"; ((converted++))
    else
      echo "    FAILED: $f" >&2; rm -f "$out"; ((failed++))
    fi
  fi
done

echo
if [[ "$DRYRUN" == 1 ]]; then
  echo "Dry run: ${#files[@]} file(s) examined, nothing written."
else
  echo "Finished: $converted converted, $skipped skipped, $failed failed. Output in: $OUTDIR/"
fi
