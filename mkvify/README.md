# mkvify

Batch-convert videos to smart-TV-friendly MKV, using the FFmpeg C libraries
directly for probing.

MKV is only a *container*. Putting a file "into MKV" is a rewrap: instant and
lossless. Re-encoding is a separate matter, and only needed when a codec inside
the file would not play on the TV. `mkvify` probes each file through
libavformat, decides per stream, and copies whatever it can.

## Requirements

- Zig **0.16.0** (see the caveat at the bottom)
- FFmpeg development headers and the `ffmpeg` binary

```sh
# Arch / CachyOS / Garuda
sudo pacman -S ffmpeg zig

# Debian / Ubuntu
sudo apt install ffmpeg libavformat-dev libavcodec-dev libavutil-dev
```

## Build

```sh
zig build test --summary all      # 12 unit tests, no video files needed
zig build -Doptimize=ReleaseFast
./zig-out/bin/mkvify --help
```

The build links `libavformat`, `libavcodec` and `libavutil` by their
pkg-config names, which resolves the include paths too — distributions
disagree about where the headers live (Arch: `/usr/include`, Debian: under an
architecture triple).

## Usage

```
mkvify [OPTIONS] [FILE|DIR ...]
```

With no argument the current directory is used. Directories are scanned for
known video extensions; files are taken as given.

| Flag | Meaning |
| --- | --- |
| `-e, --encoder ENC` | `libx264` \| `h264_nvenc` \| `h264_vaapi` (default `libx264`) |
| `-q, --crf N` | Video quality, lower is better, 18–23 is sane (default 20) |
| `--no-hevc` | Treat H.265 as unplayable and re-encode to H.264, for older TVs |
| `--vaapi-device PATH` | VAAPI render node (default `/dev/dri/renderD128`) |
| `-d, --dual-track` | Keep the original audio untouched **and** add a TV-safe AAC stereo track |
| `-n, --normalize` | EBU R128 loudness + dialogue-forward downmix |
| `-b, --audio-bitrate BR` | Bitrate for encoded stereo tracks (default `192k`) |
| `-B, --multi-bitrate BR` | Bitrate when keeping multichannel (default `384k`) |
| `-o, --outdir DIR` | Output directory (default `mkv`) |
| `-r, --recursive` | Scan directories recursively |
| `-y, --overwrite` | Overwrite existing outputs instead of skipping |
| `--dry-run` | Print the planned ffmpeg command per file, convert nothing |
| `-Q, --quiet` | Suppress ffmpeg progress output |

```sh
# Sensible default for a smart TV, using an NVIDIA GPU
mkvify -e h264_nvenc -d -n -r ~/Videos

# Old TV without H.265 support
mkvify --no-hevc -r -o /mnt/media/tv ~/Videos

# Inspect the decisions without touching anything
mkvify --dry-run *.avi
```

## Why `-d` is the flag that matters

Re-encoding can never *add* audio quality — every transcode is another lossy
generation. The usual complaint about TV playback isn't fidelity anyway, it's
dialogue buried under explosions, caused by a crude 5.1 → stereo fold that
loses the centre channel where speech lives.

`--dual-track` sidesteps the tradeoff: the original track is preserved
bit-for-bit and a processed stereo AAC track is appended beside it, flagged
`default` so the TV picks it automatically. Play the same file through a
receiver later and the untouched surround track is still there.

`--normalize` deliberately compresses dynamic range. That is exactly what you
want on TV speakers and exactly what you don't want on a good sound system —
another reason to keep both tracks.

## Design

```
src/probe.zig   libav C interop. Opens the file once via avformat_open_input
                and reads the stream table. Maps AVCodecID onto a Zig enum so
                nothing downstream touches C.
src/plan.zig    Decision engine. Pure Zig, no C and no I/O: MediaInfo +
                Options -> ffmpeg argv. Unit tested at the bottom of the file.
src/main.zig    CLI parsing, file discovery, orchestration.
```

Three consequences of doing the probing in-process:

- **No subprocess storm.** A shell version needs ~4 `ffprobe` spawns per file
  plus text parsing. This is one `avformat_open_input` and a struct.
- **The rules are testable.** Because `plan.zig` is pure, every decision is
  covered without a video on disk. `zig build test` runs 12 of them.
- **Subtitles survive.** With real stream info each subtitle track is
  classified rather than blanket-copied: MP4's `mov_text` is converted to SRT
  instead of being dropped, unmuxable tracks (closed captions) are unmapped by
  index, and output subtitle indices stay contiguous. Data streams are
  unmapped up front, which removes the retry-on-failure dance entirely.

### Decision rules

| Situation | Video | Audio |
| --- | --- | --- |
| H.264/HEVC + AAC/AC3/E-AC3/MP3 | copy | copy |
| H.264 + DTS/TrueHD/FLAC | copy | re-encode (or add track with `-d`) |
| Xvid/WMV/MPEG-2 + AAC | re-encode | copy |
| Both incompatible | re-encode | re-encode |

## Scope

Probing is fully in-process through the C API; the transcode itself is handed
to the `ffmpeg` binary with a precisely built argument vector. Doing the encode
in-process means building the whole demux → decode → filtergraph → encode →
mux pipeline against libavfilter — a much larger surface, and one worth adding
deliberately rather than by default.

Obvious next step: parallel jobs (`-j`). Probing is I/O-bound and the ffmpeg
jobs are independent.

## Zig version caveat

Written against **Zig 0.16.0**, where several std APIs differ from earlier
releases:

| Older | 0.16.0 |
| --- | --- |
| `pub fn main() !void` | `pub fn main(init: std.process.Init) !void` |
| `std.fs.File` | `std.Io.File` |
| `std.heap.GeneralPurposeAllocator` | `std.heap.DebugAllocator` |
| `std.process.argsAlloc` | `init.minimal.args.toSlice(arena)` |
| `Child.init` / `spawnAndWait` | `std.process.spawn(io, .{ .argv = ... })` |
| `Dir.makePath` | `Dir.createDirPath` |
| `Dir.realpath` | `Dir.realPath` (returns a length) |

On a different Zig version, `main.zig` is where the churn is concentrated;
`probe.zig` and `plan.zig` should port with little change.
