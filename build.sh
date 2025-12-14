#!/bin/bash

# 编译和运行 Rust 项目

set -e

echo "正在编译..."
cargo build --release

echo ""
echo "正在运行..."
cargo run --release

