#!/bin/sh

zig build test --summary all
zig build -Doptimize=ReleaseFast
