//! Media probing via the FFmpeg C libraries.
//!
//! This is the reason the tool exists in this form: instead of spawning
//! `ffprobe` four times per file and parsing its text output, we open the
//! file once through libavformat and read the stream table directly. The C
//! enums are mapped onto Zig enums here so that the rest of the program --
//! in particular the decision engine in plan.zig -- is pure Zig and can be
//! unit tested without touching a real file.

const std = @import("std");

pub const c = @cImport({
    @cInclude("libavformat/avformat.h");
    @cInclude("libavcodec/avcodec.h");
    @cInclude("libavutil/avutil.h");
    @cInclude("libavutil/dict.h");
});

pub const Error = error{
    OpenInputFailed,
    StreamInfoFailed,
};

/// Codecs we make decisions about. Anything we don't model explicitly falls
/// through to `.other`, which is always treated as "needs re-encoding".
pub const Codec = enum {
    // video
    h264,
    hevc,
    av1,
    vp9,
    mpeg4,
    mpeg2video,
    wmv3,
    vc1,
    // audio
    aac,
    ac3,
    eac3,
    mp3,
    flac,
    dts,
    truehd,
    vorbis,
    opus,
    pcm,
    wmav2,
    // subtitles
    subrip,
    ass,
    ssa,
    mov_text,
    webvtt,
    hdmv_pgs,
    dvd_subtitle,
    dvb_subtitle,
    eia_608,
    other,
};

pub const StreamKind = enum { video, audio, subtitle, attachment, data, other };

pub const Stream = struct {
    /// Index within the container, as ffmpeg's `-map 0:N` sees it.
    index: u32,
    kind: StreamKind,
    codec: Codec,
    /// Human-readable codec name from libavcodec (points at static storage).
    codec_name: []const u8,
    channels: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    language: ?[]const u8 = null,
};

pub const MediaInfo = struct {
    streams: []const Stream,
    /// Container duration in seconds, 0 when unknown.
    duration_s: f64 = 0,

    pub fn firstOf(self: MediaInfo, kind: StreamKind) ?Stream {
        for (self.streams) |s| if (s.kind == kind) return s;
        return null;
    }

    pub fn countOf(self: MediaInfo, kind: StreamKind) u32 {
        var n: u32 = 0;
        for (self.streams) |s| {
            if (s.kind == kind) n += 1;
        }
        return n;
    }
};

fn mapCodec(id: c_uint) Codec {
    return switch (id) {
        @as(c_uint, @intCast(c.AV_CODEC_ID_H264)) => .h264,
        @as(c_uint, @intCast(c.AV_CODEC_ID_HEVC)) => .hevc,
        @as(c_uint, @intCast(c.AV_CODEC_ID_AV1)) => .av1,
        @as(c_uint, @intCast(c.AV_CODEC_ID_VP9)) => .vp9,
        @as(c_uint, @intCast(c.AV_CODEC_ID_MPEG4)) => .mpeg4,
        @as(c_uint, @intCast(c.AV_CODEC_ID_MPEG2VIDEO)) => .mpeg2video,
        @as(c_uint, @intCast(c.AV_CODEC_ID_WMV3)) => .wmv3,
        @as(c_uint, @intCast(c.AV_CODEC_ID_VC1)) => .vc1,

        @as(c_uint, @intCast(c.AV_CODEC_ID_AAC)) => .aac,
        @as(c_uint, @intCast(c.AV_CODEC_ID_AC3)) => .ac3,
        @as(c_uint, @intCast(c.AV_CODEC_ID_EAC3)) => .eac3,
        @as(c_uint, @intCast(c.AV_CODEC_ID_MP3)) => .mp3,
        @as(c_uint, @intCast(c.AV_CODEC_ID_FLAC)) => .flac,
        @as(c_uint, @intCast(c.AV_CODEC_ID_DTS)) => .dts,
        @as(c_uint, @intCast(c.AV_CODEC_ID_TRUEHD)) => .truehd,
        @as(c_uint, @intCast(c.AV_CODEC_ID_VORBIS)) => .vorbis,
        @as(c_uint, @intCast(c.AV_CODEC_ID_OPUS)) => .opus,
        @as(c_uint, @intCast(c.AV_CODEC_ID_WMAV2)) => .wmav2,
        @as(c_uint, @intCast(c.AV_CODEC_ID_PCM_S16LE)) => .pcm,
        @as(c_uint, @intCast(c.AV_CODEC_ID_PCM_S24LE)) => .pcm,

        @as(c_uint, @intCast(c.AV_CODEC_ID_SUBRIP)) => .subrip,
        @as(c_uint, @intCast(c.AV_CODEC_ID_ASS)) => .ass,
        @as(c_uint, @intCast(c.AV_CODEC_ID_SSA)) => .ssa,
        @as(c_uint, @intCast(c.AV_CODEC_ID_MOV_TEXT)) => .mov_text,
        @as(c_uint, @intCast(c.AV_CODEC_ID_WEBVTT)) => .webvtt,
        @as(c_uint, @intCast(c.AV_CODEC_ID_HDMV_PGS_SUBTITLE)) => .hdmv_pgs,
        @as(c_uint, @intCast(c.AV_CODEC_ID_DVD_SUBTITLE)) => .dvd_subtitle,
        @as(c_uint, @intCast(c.AV_CODEC_ID_DVB_SUBTITLE)) => .dvb_subtitle,
        @as(c_uint, @intCast(c.AV_CODEC_ID_EIA_608)) => .eia_608,
        else => .other,
    };
}

fn mapKind(t: c_int) StreamKind {
    if (t == c.AVMEDIA_TYPE_VIDEO) return .video;
    if (t == c.AVMEDIA_TYPE_AUDIO) return .audio;
    if (t == c.AVMEDIA_TYPE_SUBTITLE) return .subtitle;
    if (t == c.AVMEDIA_TYPE_ATTACHMENT) return .attachment;
    if (t == c.AVMEDIA_TYPE_DATA) return .data;
    return .other;
}

/// Silence libav's own logging; we report problems ourselves.
pub fn quiet() void {
    c.av_log_set_level(c.AV_LOG_QUIET);
}

/// Open `path` and read its stream table. Allocated memory belongs to the
/// caller's allocator (an arena, in practice).
pub fn probe(alloc: std.mem.Allocator, path: [:0]const u8) !MediaInfo {
    var fmt: ?*c.AVFormatContext = null;
    if (c.avformat_open_input(&fmt, path.ptr, null, null) < 0)
        return Error.OpenInputFailed;
    defer c.avformat_close_input(&fmt);

    if (c.avformat_find_stream_info(fmt, null) < 0)
        return Error.StreamInfoFailed;

    const ctx = fmt.?;
    const n = ctx.nb_streams;

    var streams: std.ArrayList(Stream) = .empty;
    try streams.ensureTotalCapacity(alloc, n);

    for (0..n) |i| {
        const st = ctx.streams[i];
        const par = st.*.codecpar;

        // Stream language tag, when the container carries one.
        var lang: ?[]const u8 = null;
        const entry = c.av_dict_get(st.*.metadata, "language", null, 0);
        if (entry != null and entry.*.value != null) {
            lang = try alloc.dupe(u8, std.mem.span(entry.*.value));
        }

        streams.appendAssumeCapacity(.{
            .index = @intCast(i),
            .kind = mapKind(par.*.codec_type),
            .codec = mapCodec(@intCast(par.*.codec_id)),
            .codec_name = std.mem.span(c.avcodec_get_name(par.*.codec_id)),
            .channels = @intCast(@max(0, par.*.ch_layout.nb_channels)),
            .width = @intCast(@max(0, par.*.width)),
            .height = @intCast(@max(0, par.*.height)),
            .language = lang,
        });
    }

    const dur: f64 = if (ctx.duration > 0)
        @as(f64, @floatFromInt(ctx.duration)) / @as(f64, c.AV_TIME_BASE)
    else
        0;

    return .{ .streams = try streams.toOwnedSlice(alloc), .duration_s = dur };
}
