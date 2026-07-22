//! Decision engine.
//!
//! Pure Zig, no C and no I/O: it takes a `MediaInfo` plus the user's options
//! and produces the exact ffmpeg argument vector to run. That purity is the
//! point -- every rule below is unit tested at the bottom of this file
//! without needing a real video on disk.
//!
//! Guiding rule: re-encoding never improves quality, so a stream is copied
//! unless there is a concrete reason it cannot be.

const std = @import("std");
const probe = @import("probe.zig");
const Codec = probe.Codec;
const MediaInfo = probe.MediaInfo;

pub const Encoder = enum {
    libx264,
    h264_nvenc,
    h264_vaapi,

    pub fn parse(s: []const u8) ?Encoder {
        return std.meta.stringToEnum(Encoder, s);
    }
};

pub const Options = struct {
    encoder: Encoder = .libx264,
    crf: u8 = 20,
    dual_track: bool = false,
    normalize: bool = false,
    /// Treat H.265 as unplayable and re-encode it down to H.264.
    no_hevc: bool = false,
    audio_bitrate: []const u8 = "192k",
    multi_bitrate: []const u8 = "384k",
    vaapi_device: []const u8 = "/dev/dri/renderD128",
};

/// Dialogue-forward downmix. ffmpeg's default 5.1->stereo fold buries the
/// centre channel, which is exactly where speech lives; this weights it back
/// up so dialogue stays audible on TV speakers.
pub const downmix = "pan=stereo|FL=0.5*FC+0.707*FL+0.5*BL+0.5*SL|FR=0.5*FC+0.707*FR+0.5*BR+0.5*SR";
/// EBU R128 loudness normalisation, targeting the broadcast standard.
pub const loudnorm = "loudnorm=I=-16:TP=-1.5:LRA=11";

pub const VideoAction = enum { copy, encode };
pub const AudioAction = enum {
    /// Source is already playable: pass the stream through untouched.
    copy,
    /// Source is unplayable and dual-track is off: replace it.
    encode,
    /// Keep the original bit-for-bit and append a TV-safe stereo track.
    dual,
};
pub const SubtitleAction = enum { copy, to_srt, drop };

pub const Plan = struct {
    argv: []const []const u8,
    video: VideoAction,
    audio: AudioAction,
    /// True when nothing at all is re-encoded: a pure, lossless rewrap.
    lossless: bool,

    pub fn note(self: Plan, buf: []u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        if (self.lossless) {
            w.writeAll("rewrap only, lossless") catch {};
            return w.buffered();
        }
        w.print("video {t}, audio {t}", .{ self.video, self.audio }) catch {};
        return w.buffered();
    }
};

/// Video codecs a smart TV can be expected to decode.
fn videoIsSafe(codec: Codec, opts: Options) bool {
    return switch (codec) {
        .h264 => true,
        .hevc => !opts.no_hevc,
        else => false,
    };
}

/// Audio codecs a smart TV can be expected to decode. DTS and TrueHD are the
/// usual offenders: the video plays fine but there is no sound.
fn audioIsSafe(codec: Codec) bool {
    return switch (codec) {
        .aac, .ac3, .eac3, .mp3 => true,
        else => false,
    };
}

/// Matroska accepts most subtitle formats directly. MP4's mov_text is the
/// notable exception -- rather than dropping those tracks (which is what a
/// naive `-c:s copy` forces you into) we convert them to SRT and keep them.
fn subtitleAction(codec: Codec) SubtitleAction {
    return switch (codec) {
        .subrip, .ass, .ssa, .webvtt, .hdmv_pgs, .dvd_subtitle, .dvb_subtitle => .copy,
        .mov_text => .to_srt,
        // Closed captions and anything unrecognised cannot be muxed into MKV.
        .eia_608, .other => .drop,
        else => .drop,
    };
}

const Builder = struct {
    list: std.ArrayList([]const u8) = .empty,
    alloc: std.mem.Allocator,

    fn add(self: *Builder, arg: []const u8) !void {
        try self.list.append(self.alloc, arg);
    }
    fn addFmt(self: *Builder, comptime f: []const u8, args: anytype) !void {
        try self.list.append(self.alloc, try std.fmt.allocPrint(self.alloc, f, args));
    }
};

/// Build the ffmpeg invocation for one file.
pub fn build(
    alloc: std.mem.Allocator,
    info: MediaInfo,
    input: []const u8,
    output: []const u8,
    opts: Options,
) !Plan {
    var b = Builder{ .alloc = alloc };

    const v = info.firstOf(.video);
    const a = info.firstOf(.audio);
    const n_audio = info.countOf(.audio);

    const v_safe = if (v) |s| videoIsSafe(s.codec, opts) else true;
    const a_safe = if (a) |s| audioIsSafe(s.codec) else true;
    const channels = if (a) |s| s.channels else 2;

    const video_action: VideoAction = if (v_safe) .copy else .encode;

    // Dual-track applies whenever the original audio would otherwise be
    // altered -- an unplayable codec, or a requested normalisation. The
    // original is always preserved and the new track carries the processing.
    const audio_action: AudioAction = blk: {
        if (a == null) break :blk .copy;
        if (opts.dual_track and (!a_safe or opts.normalize)) break :blk .dual;
        if (a_safe and !opts.normalize) break :blk .copy;
        break :blk .encode;
    };

    try b.add("ffmpeg");
    try b.add("-hide_banner");
    try b.add("-y");

    // VAAPI needs its device selected before the input is opened.
    if (video_action == .encode and opts.encoder == .h264_vaapi) {
        try b.add("-vaapi_device");
        try b.add(opts.vaapi_device);
    }

    try b.add("-i");
    try b.add(input);

    // --- stream mapping ---------------------------------------------------
    try b.add("-map");
    try b.add("0");
    // Data streams (timecode tracks and similar) routinely fail to mux into
    // Matroska and carry nothing worth keeping.
    try b.add("-map");
    try b.add("-0:d?");

    if (audio_action == .dual) {
        try b.add("-map");
        try b.add("0:a:0");
    }

    // Drop subtitle streams MKV cannot hold, by absolute stream index.
    for (info.streams) |s| {
        if (s.kind != .subtitle) continue;
        if (subtitleAction(s.codec) == .drop) {
            try b.add("-map");
            try b.addFmt("-0:{d}", .{s.index});
        }
    }

    // --- video ------------------------------------------------------------
    switch (video_action) {
        .copy => {
            try b.add("-c:v");
            try b.add("copy");
        },
        .encode => switch (opts.encoder) {
            .libx264 => {
                try b.add("-c:v");
                try b.add("libx264");
                try b.add("-crf");
                try b.addFmt("{d}", .{opts.crf});
                try b.add("-preset");
                try b.add("medium");
            },
            .h264_nvenc => {
                try b.add("-c:v");
                try b.add("h264_nvenc");
                try b.add("-cq");
                try b.addFmt("{d}", .{opts.crf});
                try b.add("-preset");
                try b.add("p5");
            },
            .h264_vaapi => {
                try b.add("-vf");
                try b.add("format=nv12,hwupload");
                try b.add("-c:v");
                try b.add("h264_vaapi");
                try b.add("-qp");
                try b.addFmt("{d}", .{opts.crf});
            },
        },
    }

    // --- audio ------------------------------------------------------------
    switch (audio_action) {
        .copy => {
            try b.add("-c:a");
            try b.add("copy");
        },
        .encode => {
            var filters: std.ArrayList([]const u8) = .empty;
            if (channels > 2 and opts.normalize) try filters.append(alloc, downmix);
            if (opts.normalize) try filters.append(alloc, loudnorm);

            try b.add("-c:a");
            try b.add("aac");
            try b.add("-b:a");
            // Keeping multichannel deserves a more generous bitrate; once we
            // fold to stereo the stereo rate applies.
            try b.add(if (channels > 2 and filters.items.len == 0)
                opts.multi_bitrate
            else
                opts.audio_bitrate);

            if (filters.items.len > 0) {
                try b.add("-af");
                try b.add(try std.mem.join(alloc, ",", filters.items));
                try b.add("-ac");
                try b.add("2");
            }
        },
        .dual => {
            // Every original stream is copied; the appended track is index
            // `n_audio` among the output's audio streams.
            try b.add("-c:a");
            try b.add("copy");

            try b.addFmt("-c:a:{d}", .{n_audio});
            try b.add("aac");
            try b.addFmt("-b:a:{d}", .{n_audio});
            try b.add(opts.audio_bitrate);
            try b.addFmt("-ac:{d}", .{n_audio});
            try b.add("2");

            var filters: std.ArrayList([]const u8) = .empty;
            if (channels > 2) try filters.append(alloc, downmix);
            if (opts.normalize) try filters.append(alloc, loudnorm);
            if (filters.items.len > 0) {
                try b.addFmt("-filter:a:{d}", .{n_audio});
                try b.add(try std.mem.join(alloc, ",", filters.items));
            }

            try b.addFmt("-metadata:s:a:{d}", .{n_audio});
            try b.add("title=Stereo AAC (TV)");
            // Point the TV at the compatible track without destroying the
            // original's place in the file.
            try b.add("-disposition:a:0");
            try b.add("0");
            try b.addFmt("-disposition:a:{d}", .{n_audio});
            try b.add("default");
        },
    }

    // --- subtitles --------------------------------------------------------
    var out_idx: u32 = 0;
    for (info.streams) |s| {
        if (s.kind != .subtitle) continue;
        switch (subtitleAction(s.codec)) {
            .drop => {},
            .copy => {
                try b.addFmt("-c:s:{d}", .{out_idx});
                try b.add("copy");
                out_idx += 1;
            },
            .to_srt => {
                try b.addFmt("-c:s:{d}", .{out_idx});
                try b.add("srt");
                out_idx += 1;
            },
        }
    }

    try b.add(output);

    return .{
        .argv = try b.list.toOwnedSlice(alloc),
        .video = video_action,
        .audio = audio_action,
        .lossless = video_action == .copy and audio_action == .copy,
    };
}

// ---------------------------------------------------------------------------
// Tests: the whole reason the decision logic is kept free of C and I/O.
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mk(streams: []const probe.Stream) MediaInfo {
    return .{ .streams = streams };
}

fn hasSeq(argv: []const []const u8, seq: []const []const u8) bool {
    if (seq.len == 0 or argv.len < seq.len) return false;
    var i: usize = 0;
    outer: while (i + seq.len <= argv.len) : (i += 1) {
        for (seq, 0..) |want, j| {
            if (!std.mem.eql(u8, argv[i + j], want)) continue :outer;
        }
        return true;
    }
    return false;
}

fn has(argv: []const []const u8, needle: []const u8) bool {
    for (argv) |a| if (std.mem.eql(u8, a, needle)) return true;
    return false;
}

test "TV-safe input is rewrapped losslessly, nothing re-encoded" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
        .{ .index = 1, .kind = .audio, .codec = .aac, .codec_name = "aac", .channels = 2 },
    });
    const p = try build(arena.allocator(), info, "in.mp4", "out.mkv", .{});
    try testing.expect(p.lossless);
    try testing.expect(hasSeq(p.argv, &.{ "-c:v", "copy" }));
    try testing.expect(hasSeq(p.argv, &.{ "-c:a", "copy" }));
    try testing.expect(!has(p.argv, "libx264"));
}

test "unplayable audio alone does not trigger a video re-encode" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
        .{ .index = 1, .kind = .audio, .codec = .dts, .codec_name = "dts", .channels = 6 },
    });
    const p = try build(arena.allocator(), info, "in.mkv", "out.mkv", .{});
    try testing.expectEqual(.copy, p.video);
    try testing.expectEqual(.encode, p.audio);
    try testing.expect(hasSeq(p.argv, &.{ "-c:v", "copy" }));
    try testing.expect(hasSeq(p.argv, &.{ "-c:a", "aac" }));
}

test "old video codec alone does not trigger an audio re-encode" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .mpeg4, .codec_name = "mpeg4" },
        .{ .index = 1, .kind = .audio, .codec = .mp3, .codec_name = "mp3", .channels = 2 },
    });
    const p = try build(arena.allocator(), info, "in.avi", "out.mkv", .{});
    try testing.expectEqual(.encode, p.video);
    try testing.expectEqual(.copy, p.audio);
}

test "no-hevc forces H.265 down to H.264" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .hevc, .codec_name = "hevc" },
        .{ .index = 1, .kind = .audio, .codec = .aac, .codec_name = "aac", .channels = 2 },
    });
    const keep = try build(arena.allocator(), info, "i", "o", .{});
    try testing.expectEqual(.copy, keep.video);

    const force = try build(arena.allocator(), info, "i", "o", .{ .no_hevc = true });
    try testing.expectEqual(.encode, force.video);
    try testing.expect(has(force.argv, "libx264"));
}

test "dual-track preserves the original when normalising already-safe audio" {
    // Regression: the original must never be replaced when --dual-track is on,
    // even for audio that needed no codec change.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
        .{ .index = 1, .kind = .audio, .codec = .aac, .codec_name = "aac", .channels = 2 },
    });
    const p = try build(arena.allocator(), info, "i", "o", .{
        .dual_track = true,
        .normalize = true,
    });
    try testing.expectEqual(.dual, p.audio);
    try testing.expect(hasSeq(p.argv, &.{ "-c:a", "copy" })); // original untouched
    try testing.expect(hasSeq(p.argv, &.{ "-c:a:1", "aac" })); // added track
    try testing.expect(hasSeq(p.argv, &.{ "-disposition:a:1", "default" }));
}

test "normalisation reaches the added dual-track, with the dialogue downmix" {
    // Regression: --normalize must apply to the track the TV actually plays.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
        .{ .index = 1, .kind = .audio, .codec = .flac, .codec_name = "flac", .channels = 6 },
    });
    const p = try build(arena.allocator(), info, "i", "o", .{
        .dual_track = true,
        .normalize = true,
    });
    const chain = downmix ++ "," ++ loudnorm;
    try testing.expect(hasSeq(p.argv, &.{ "-filter:a:1", chain }));
}

test "multichannel kept without filters gets the higher bitrate" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
        .{ .index = 1, .kind = .audio, .codec = .dts, .codec_name = "dts", .channels = 6 },
    });
    const p = try build(arena.allocator(), info, "i", "o", .{});
    try testing.expect(hasSeq(p.argv, &.{ "-b:a", "384k" }));
}

test "mov_text subtitles are converted rather than dropped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
        .{ .index = 1, .kind = .audio, .codec = .aac, .codec_name = "aac", .channels = 2 },
        .{ .index = 2, .kind = .subtitle, .codec = .mov_text, .codec_name = "mov_text" },
    });
    const p = try build(arena.allocator(), info, "i", "o", .{});
    try testing.expect(hasSeq(p.argv, &.{ "-c:s:0", "srt" }));
    try testing.expect(!has(p.argv, "-0:2"));
}

test "unmuxable subtitles are dropped and output indices stay contiguous" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
        .{ .index = 1, .kind = .audio, .codec = .aac, .codec_name = "aac", .channels = 2 },
        .{ .index = 2, .kind = .subtitle, .codec = .eia_608, .codec_name = "eia_608" },
        .{ .index = 3, .kind = .subtitle, .codec = .subrip, .codec_name = "subrip" },
    });
    const p = try build(arena.allocator(), info, "i", "o", .{});
    // The caption track is unmapped...
    try testing.expect(hasSeq(p.argv, &.{ "-map", "-0:2" }));
    // ...and the surviving track is still output subtitle 0, not 1.
    try testing.expect(hasSeq(p.argv, &.{ "-c:s:0", "copy" }));
    try testing.expect(!has(p.argv, "-c:s:1"));
}

test "vaapi device is set before the input, not after" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .mpeg4, .codec_name = "mpeg4" },
        .{ .index = 1, .kind = .audio, .codec = .aac, .codec_name = "aac", .channels = 2 },
    });
    const p = try build(arena.allocator(), info, "i", "o", .{ .encoder = .h264_vaapi });
    var dev: usize = 0;
    var inp: usize = 0;
    for (p.argv, 0..) |x, i| {
        if (std.mem.eql(u8, x, "-vaapi_device")) dev = i;
        if (std.mem.eql(u8, x, "-i")) inp = i;
    }
    try testing.expect(dev != 0 and dev < inp);
}

test "audio-less input does not crash the planner" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const info = mk(&.{
        .{ .index = 0, .kind = .video, .codec = .h264, .codec_name = "h264" },
    });
    const p = try build(arena.allocator(), info, "i", "o", .{ .normalize = true });
    try testing.expectEqual(.copy, p.audio);
    try testing.expect(p.lossless);
}
