#!/bin/bash
# 速度测试脚本

echo "=== Fast-TCP-VPN 速度测试 ==="
echo ""
echo "此脚本将在本地启动虚拟服务端和客户端进行速度测试"
echo "测试时长: 10秒"
echo ""

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "错误: 需要 root 权限运行"
    echo "请使用: sudo ./test_speed.sh"
    exit 1
fi

# 编译
echo "正在编译..."
cargo build --release --bin speed_test 2>&1 | grep -E "(Compiling|Finished|error)" || true
echo ""

BINARY="./target/release/speed_test"

if [ ! -f "$BINARY" ]; then
    echo "错误: 找不到编译后的二进制文件"
    exit 1
fi

# 启动服务端（后台运行）
echo "启动虚拟服务端..."
$BINARY server 9000 15 > /tmp/speed_test_server.log 2>&1 &
SERVER_PID=$!
echo "服务端 PID: $SERVER_PID"
echo ""

# 等待服务端启动
sleep 2

# 启动客户端
echo "启动虚拟客户端..."
echo ""
$BINARY client 127.0.0.1 9000 10 1400

# 等待服务端完成
echo ""
echo "等待服务端完成..."
sleep 2

# 停止服务端
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== 服务端日志 ==="
tail -20 /tmp/speed_test_server.log

echo ""
echo "测试完成！"
