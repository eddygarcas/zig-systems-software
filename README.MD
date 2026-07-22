# zig-systems-software

A collection of small, self-contained Zig projects — systems programming
experiments written to explore the language rather than to ship a product.
Each directory is an independent `zig build` project with its own
`build.zig` and `build.zig.zon`; there is no workspace-level build.

Themes that recur: comptime-driven parsing, allocator design, C interop,
WebAssembly targets, and cryptography.

## Projects

| Project | What it is |
| --- | --- |
| [`mkvify`](mkvify) | Batch video → MKV converter for smart-TV playback. Probes files through the FFmpeg C libraries (`libavformat`/`libavcodec`) instead of shelling out to `ffprobe`. |
| [`aead-encryption`](aead-encryption) | Authenticated file encryption with ChaCha20-Poly1305. PBKDF2-HMAC-SHA256 key derivation, chunked format with a per-chunk nonce and Poly1305 tag. |
| [`csv-validator`](csv-validator) | Schema-driven CSV validator compiled to WebAssembly, with a browser front-end that runs validation entirely client-side. |
| [`json-parser`](json-parser) | Comptime JSON parser — `JsonParser(T)` generates a parser for the target type, so the shape of `T` drives the parse. |
| [`toon-parser`](toon-parser) | The same comptime approach applied to an indentation-sensitive format. |
| [`bump-allocator`](bump-allocator) | Thread-safe bump/arena allocator over a fixed buffer. O(1) allocation, no individual free, bulk reclaim via `reset()`. |
| [`xor-encryption`](xor-encryption) | XOR cipher CLI. Educational — trivially broken by frequency analysis, and labelled as such. |

## Building

Each project stands alone:

```sh
cd <project>
zig build                      # build
zig build test --summary all   # run its tests
zig build -Doptimize=ReleaseFast
```

`csv-validator` targets WebAssembly and is driven from `index.html`:

```sh
cd csv-validator
zig build -Dtarget=wasm32-freestanding -Doptimize=ReleaseSmall
python3 -m http.server        # then open index.html
```

`mkvify` is the one project with an external dependency — it links the
FFmpeg C libraries and needs their development headers:

```sh
sudo pacman -S ffmpeg                       # Arch
sudo apt install ffmpeg libavformat-dev libavcodec-dev libavutil-dev
```

## Zig version

Everything targets **Zig 0.16**, but each `build.zig.zon` pins a different
`0.16.0-dev` nightly, so behaviour varies against the 0.16.0 release. Current
state on stable 0.16.0:

| Project | 0.16.0 release |
| --- | --- |
| `aead-encryption` | builds |
| `bump-allocator` | builds |
| `csv-validator` | builds |
| `json-parser` | builds |
| `mkvify` | builds |
| `toon-parser` | library-shaped; `build.zig` still builds an executable and no `main` exists |
| `xor-encryption` | uses `std.heap.GeneralPurposeAllocator`, renamed to `DebugAllocator` |

Zig 0.16 moved a lot of std around. The renames that account for most breakage
in older code here:

| Older | 0.16 |
| --- | --- |
| `pub fn main() !void` | `pub fn main(init: std.process.Init) !void` |
| `std.fs.File` | `std.Io.File` |
| `std.heap.GeneralPurposeAllocator` | `std.heap.DebugAllocator` |
| `std.process.argsAlloc` | `init.minimal.args.toSlice(arena)` |
| `Child.init` / `spawnAndWait` | `std.process.spawn(io, .{ .argv = ... })` |
| `Dir.makePath` / `Dir.realpath` | `Dir.createDirPath` / `Dir.realPath` |
| `std.ArrayList` (managed) | unmanaged: `.empty`, `append(alloc, x)` |

## Layout

```
<project>/
  build.zig
  build.zig.zon
  src/
    main.zig      entry point (or the exported surface, for library-shaped projects)
    root.zig      module root where one is used
```

## Notes

Tests live beside the code in `test` blocks and run with `zig build test`.
`mkvify` carries the most (12), because its decision logic is deliberately
kept free of C and I/O so the rules can be tested without a media file on
disk — a pattern worth reusing anywhere a thin C layer wraps real logic.
