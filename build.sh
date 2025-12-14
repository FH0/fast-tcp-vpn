#!/bin/bash

# 编译和运行 Rust 项目

set -e

# 解析参数
RUN_TEST=""
TEST_NAME=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -t)
            RUN_TEST=1
            if [[ $# -gt 1 ]] && [[ ! "$2" =~ ^- ]]; then
                TEST_NAME="$2"
                shift 2
            else
                shift
            fi
            ;;
        *)
            echo "未知参数: $1"
            echo "用法: $0 [-t [测试名称]]"
            exit 1
            ;;
    esac
done

# 如果指定了运行测试
if [ -n "$RUN_TEST" ]; then
    if [ -n "$TEST_NAME" ]; then
        echo "正在运行测试: $TEST_NAME"
        timeout 20 cargo test --release -- --nocapture "$TEST_NAME"
    else
        echo "正在运行所有测试..."
        timeout 20 cargo test --release -- --nocapture
    fi
    exit 0
fi

echo "正在编译..."
cargo build --release

echo ""
echo "正在运行..."
cargo run --release

