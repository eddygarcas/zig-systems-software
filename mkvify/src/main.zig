//! mkvify -- batch-convert videos to smart-TV-friendly MKV.
//!
//! MKV is only a container: putting a file "into MKV" is a rewrap, which is
//! instant and lossless. Re-encoding is a separate matter and only happens
//! when a codec inside the file would not play on the TV. This tool probes
//! each file through libavformat, decides per stream, and copies whatever it
//! can.

const std = @import("std");
const probe = @import("probe.zig");
const plan = @import("plan.zig");

const version = "1.0.0";

const video_exts = [_][]const u8{
    ".mp4", ".avi",  ".mov",  ".wmv", ".flv", ".mpg", ".mpeg",
    ".m4v", ".ts",   ".webm", ".divx", ".vob", ".3gp", ".mkv",
    ".m2ts", ".mts", ".ogv",  ".rm",  ".asf",
};

const Config = struct {
    opts: plan.Options = .{},
    outdir: []const u8 = "mkv",
    recursive: bool = false,
    overwrite: bool = false,
    dry_run: bool = false,
    quiet: bool = false,
    targets: std.ArrayList([]const u8) = .empty,
};

const usage_text =
    \\mkvify — batch-convert videos to smart-TV-friendly MKV
    \\
    \\USAGE
    \\  mkvify [OPTIONS] [FILE|DIR ...]
    \\
    \\  With no FILE or DIR, the current directory is used. Directories are
    \\  scanned for known video extensions; files are taken as given.
    \\
    \\VIDEO OPTIONS
    \\  -e, --encoder ENC        libx264 | h264_nvenc | h264_vaapi  (default: libx264)
    \\                           GPU encoders are much faster; libx264 gives the
    \\                           best quality per bitrate.
    \\  -q, --crf N              Video quality, lower is better, sane range 18-23
    \\                           (default: 20). Only applies when re-encoding.
    \\      --no-hevc            Treat H.265/HEVC as unplayable and re-encode it
    \\                           to H.264. Use this for older TVs.
    \\      --vaapi-device PATH  VAAPI render node (default: /dev/dri/renderD128)
    \\
    \\AUDIO OPTIONS
    \\  -d, --dual-track         Keep the original audio untouched AND add a
    \\                           TV-safe AAC stereo track beside it, flagged as
    \\                           default. No quality loss; the TV picks the
    \\                           compatible track.
    \\  -n, --normalize          EBU R128 loudness normalisation plus a
    \\                           dialogue-forward downmix, so speech stays
    \\                           audible on TV speakers. Forces an audio encode.
    \\  -b, --audio-bitrate BR   Bitrate for encoded stereo tracks (default: 192k)
    \\  -B, --multi-bitrate BR   Bitrate when keeping multichannel (default: 384k)
    \\
    \\OUTPUT OPTIONS
    \\  -o, --outdir DIR         Output directory (default: mkv)
    \\  -r, --recursive          Scan directories recursively
    \\  -y, --overwrite          Overwrite existing outputs instead of skipping
    \\      --dry-run            Print what would be done, convert nothing
    \\  -Q, --quiet              Suppress ffmpeg progress output
    \\
    \\  -h, --help               Show this help
    \\  -V, --version            Show version
    \\
    \\EXAMPLES
    \\  # Sensible default for a smart TV, using an NVIDIA GPU
    \\  mkvify -e h264_nvenc -d -n ~/Videos
    \\
    \\  # Old TV without H.265 support, recursing through subfolders
    \\  mkvify --no-hevc -r -o /mnt/media/tv ~/Videos
    \\
    \\  # Inspect the decisions without touching anything
    \\  mkvify --dry-run *.avi
    \\
;

fn fail(comptime f: []const u8, args: anytype) noreturn {
    std.debug.print("mkvify: " ++ f ++ "\n", args);
    std.debug.print("Try 'mkvify --help' for more information.\n", .{});
    std.process.exit(2);
}

fn nextArg(args: []const [:0]const u8, i: *usize, flag: []const u8) []const u8 {
    i.* += 1;
    if (i.* >= args.len) fail("option '{s}' requires an argument", .{flag});
    return args[i.*];
}

fn hasVideoExt(name: []const u8) bool {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return false;
    const ext = name[dot..];
    for (video_exts) |e| {
        if (std.ascii.eqlIgnoreCase(ext, e)) return true;
    }
    return false;
}

/// Expand the positional arguments into a concrete list of files to convert.
fn collect(
    alloc: std.mem.Allocator,
    io: std.Io,
    cfg: *const Config,
    out: *std.ArrayList([]const u8),
) !void {
    const cwd = std.Io.Dir.cwd();
    for (cfg.targets.items) |target| {
        const st = cwd.statFile(io, target, .{}) catch |err| {
            fail("cannot access '{s}': {t}", .{ target, err });
        };
        if (st.kind == .file) {
            try out.append(alloc, target);
            continue;
        }
        if (st.kind != .directory) continue;

        var dir = cwd.openDir(io, target, .{ .iterate = true }) catch |err| {
            fail("cannot open directory '{s}': {t}", .{ target, err });
        };
        defer dir.close(io);

        if (cfg.recursive) {
            var walker = try dir.walk(alloc);
            defer walker.deinit();
            while (try walker.next(io)) |entry| {
                if (entry.kind != .file or !hasVideoExt(entry.path)) continue;
                try out.append(alloc, try std.fs.path.join(alloc, &.{ target, entry.path }));
            }
        } else {
            var it = dir.iterate();
            while (try it.next(io)) |entry| {
                if (entry.kind != .file or !hasVideoExt(entry.name)) continue;
                try out.append(alloc, try std.fs.path.join(alloc, &.{ target, entry.name }));
            }
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var cfg = Config{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            var buf: [4096]u8 = undefined;
            var w = std.Io.File.stdout().writer(io, &buf);
            try w.interface.writeAll(usage_text);
            try w.interface.flush();
            return;
        } else if (std.mem.eql(u8, a, "-V") or std.mem.eql(u8, a, "--version")) {
            var buf: [64]u8 = undefined;
            var w = std.Io.File.stdout().writer(io, &buf);
            try w.interface.print("mkvify {s}\n", .{version});
            try w.interface.flush();
            return;
        } else if (std.mem.eql(u8, a, "-e") or std.mem.eql(u8, a, "--encoder")) {
            const v = nextArg(args, &i, a);
            cfg.opts.encoder = plan.Encoder.parse(v) orelse
                fail("invalid encoder '{s}' (expected libx264, h264_nvenc or h264_vaapi)", .{v});
        } else if (std.mem.eql(u8, a, "-q") or std.mem.eql(u8, a, "--crf")) {
            const v = nextArg(args, &i, a);
            cfg.opts.crf = std.fmt.parseInt(u8, v, 10) catch
                fail("--crf must be a number, got '{s}'", .{v});
            if (cfg.opts.crf > 51) fail("--crf must be 0-51, got {d}", .{cfg.opts.crf});
        } else if (std.mem.eql(u8, a, "--no-hevc")) {
            cfg.opts.no_hevc = true;
        } else if (std.mem.eql(u8, a, "--vaapi-device")) {
            cfg.opts.vaapi_device = nextArg(args, &i, a);
        } else if (std.mem.eql(u8, a, "-d") or std.mem.eql(u8, a, "--dual-track")) {
            cfg.opts.dual_track = true;
        } else if (std.mem.eql(u8, a, "-n") or std.mem.eql(u8, a, "--normalize") or
            std.mem.eql(u8, a, "--normalise"))
        {
            cfg.opts.normalize = true;
        } else if (std.mem.eql(u8, a, "-b") or std.mem.eql(u8, a, "--audio-bitrate")) {
            cfg.opts.audio_bitrate = nextArg(args, &i, a);
        } else if (std.mem.eql(u8, a, "-B") or std.mem.eql(u8, a, "--multi-bitrate")) {
            cfg.opts.multi_bitrate = nextArg(args, &i, a);
        } else if (std.mem.eql(u8, a, "-o") or std.mem.eql(u8, a, "--outdir")) {
            cfg.outdir = nextArg(args, &i, a);
        } else if (std.mem.eql(u8, a, "-r") or std.mem.eql(u8, a, "--recursive")) {
            cfg.recursive = true;
        } else if (std.mem.eql(u8, a, "-y") or std.mem.eql(u8, a, "--overwrite")) {
            cfg.overwrite = true;
        } else if (std.mem.eql(u8, a, "--dry-run")) {
            cfg.dry_run = true;
        } else if (std.mem.eql(u8, a, "-Q") or std.mem.eql(u8, a, "--quiet")) {
            cfg.quiet = true;
        } else if (std.mem.eql(u8, a, "--")) {
            for (args[i + 1 ..]) |rest| try cfg.targets.append(arena, rest);
            break;
        } else if (a.len > 1 and a[0] == '-') {
            fail("unknown option '{s}'", .{a});
        } else {
            try cfg.targets.append(arena, a);
        }
    }

    if (cfg.targets.items.len == 0) try cfg.targets.append(arena, ".");

    if (cfg.opts.encoder == .h264_vaapi) {
        _ = std.Io.Dir.cwd().statFile(io, cfg.opts.vaapi_device, .{}) catch
            fail("VAAPI device '{s}' not found", .{cfg.opts.vaapi_device});
    }

    probe.quiet();

    var files: std.ArrayList([]const u8) = .empty;
    try collect(arena, io, &cfg, &files);

    var stdout_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &stdout_buf);
    const w = &out.interface;

    if (files.items.len == 0) {
        try w.writeAll("mkvify: no video files found\n");
        try w.flush();
        return;
    }

    if (!cfg.dry_run) {
        std.Io.Dir.cwd().createDirPath(io, cfg.outdir) catch |err|
            fail("cannot create output directory '{s}': {t}", .{ cfg.outdir, err });
    }

    // Resolve the output directory so we never re-process our own results.
    var outdir_real: ?[]const u8 = null;
    if (std.Io.Dir.cwd().openDir(io, cfg.outdir, .{})) |d| {
        var dd = d;
        defer dd.close(io);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        if (dd.realPath(io, &buf)) |n| {
            outdir_real = try arena.dupe(u8, buf[0..n]);
        } else |_| {}
    } else |_| {}

    var converted: u32 = 0;
    var skipped: u32 = 0;
    var failed: u32 = 0;

    for (files.items) |path| {
        // Skip anything already living in the output directory.
        if (outdir_real) |od| {
            const dirname = std.fs.path.dirname(path) orelse ".";
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            if (std.Io.Dir.cwd().openDir(io, dirname, .{})) |d| {
                var dd = d;
                defer dd.close(io);
                if (dd.realPath(io, &buf)) |n| {
                    if (std.mem.eql(u8, buf[0..n], od)) continue;
                } else |_| {}
            } else |_| {}
        }

        const stem = std.fs.path.stem(path);
        const output = try std.fs.path.join(arena, &.{
            cfg.outdir,
            try std.fmt.allocPrint(arena, "{s}.mkv", .{stem}),
        });

        if (!cfg.overwrite) {
            if (std.Io.Dir.cwd().statFile(io, output, .{})) |_| {
                try w.print("skip (exists): {s}\n", .{output});
                skipped += 1;
                continue;
            } else |_| {}
        }

        const path_z = try arena.dupeZ(u8, path);
        const info = probe.probe(arena, path_z) catch |err| {
            try w.print("!! cannot probe {s}: {t}\n", .{ path, err });
            failed += 1;
            continue;
        };

        const p = try plan.build(arena, info, path, output, cfg.opts);

        const v = info.firstOf(.video);
        const a = info.firstOf(.audio);
        var note_buf: [128]u8 = undefined;
        try w.print("==> {s}  [v:{s} a:{s} {d}ch]  ({s})\n", .{
            path,
            if (v) |s| s.codec_name else "none",
            if (a) |s| s.codec_name else "none",
            if (a) |s| s.channels else 0,
            p.note(&note_buf),
        });

        if (cfg.dry_run) {
            try w.writeAll("    ");
            for (p.argv, 0..) |arg, n| {
                if (n > 0) try w.writeAll(" ");
                // Quote anything a shell would mangle, so the printed line is
                // copy-pasteable.
                if (std.mem.indexOfAny(u8, arg, " |*?'\"") != null) {
                    try w.print("'{s}'", .{arg});
                } else {
                    try w.writeAll(arg);
                }
            }
            try w.writeAll("\n");
            try w.flush();
            continue;
        }

        // Assemble the final argv with the requested log level.
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(arena, p.argv[0]);
        try argv.append(arena, "-loglevel");
        try argv.append(arena, if (cfg.quiet) "error" else "warning");
        if (!cfg.quiet) try argv.append(arena, "-stats");
        try argv.appendSlice(arena, p.argv[1..]);

        try w.flush(); // let ffmpeg's output interleave cleanly

        var child = std.process.spawn(io, .{ .argv = argv.items }) catch |err| {
            try w.print("    FAILED to launch ffmpeg: {t}\n", .{err});
            failed += 1;
            continue;
        };
        const term = try child.wait(io);

        switch (term) {
            .exited => |code| if (code == 0) {
                try w.writeAll("    done\n");
                converted += 1;
            } else {
                try w.print("    FAILED (ffmpeg exit {d})\n", .{code});
                std.Io.Dir.cwd().deleteFile(io, output) catch {};
                failed += 1;
            },
            else => {
                try w.print("    FAILED ({any})\n", .{term});
                std.Io.Dir.cwd().deleteFile(io, output) catch {};
                failed += 1;
            },
        }
        try w.flush();
    }

    if (cfg.dry_run) {
        try w.print("\nDry run: {d} file(s) examined, nothing written.\n", .{files.items.len});
    } else {
        try w.print("\nFinished: {d} converted, {d} skipped, {d} failed. Output in: {s}/\n", .{
            converted, skipped, failed, cfg.outdir,
        });
    }
    try w.flush();

    if (failed > 0) std.process.exit(1);
}

test {
    _ = plan;
}
