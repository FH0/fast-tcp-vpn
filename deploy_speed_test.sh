#!/bin/bash
set -e

SERVER="root@38.175.192.236"
BINARY="./target/release/speed_test"
SERVICE_FILE="./speed_test_server.service"

echo "=== 部署 Speed Test 到服务器 ==="
echo "服务器: $SERVER"
echo ""

# 检查二进制文件是否存在
if [ ! -f "$BINARY" ]; then
    echo "[错误] 二进制文件不存在: $BINARY"
    echo "请先运行: cargo build --release --bin speed_test"
    exit 1
fi

# 检查 service 文件是否存在
if [ ! -f "$SERVICE_FILE" ]; then
    echo "[错误] Service 文件不存在: $SERVICE_FILE"
    exit 1
fi

echo "[1/5] 上传二进制文件..."
scp "$BINARY" "$SERVER:/tmp/speed_test"

echo "[2/5] 上传 systemd service 文件..."
scp "$SERVICE_FILE" "$SERVER:/tmp/speed_test_server.service"

echo "[3/5] 安装二进制文件和服务..."
ssh "$SERVER" << 'ENDSSH'
set -e

# 停止旧服务（如果存在）
if systemctl is-active --quiet speed_test_server; then
    echo "停止旧服务..."
    systemctl stop speed_test_server
fi

# 安装二进制文件
echo "安装二进制文件到 /usr/local/bin/..."
mv /tmp/speed_test /usr/local/bin/speed_test
chmod +x /usr/local/bin/speed_test

# 安装 systemd service
echo "安装 systemd service..."
mv /tmp/speed_test_server.service /etc/systemd/system/speed_test_server.service
chmod 644 /etc/systemd/system/speed_test_server.service

# 重新加载 systemd
echo "重新加载 systemd..."
systemctl daemon-reload

# 启用服务
echo "启用服务..."
systemctl enable speed_test_server

echo "安装完成！"
ENDSSH

echo "[4/5] 启动服务..."
ssh "$SERVER" "systemctl start speed_test_server"

echo "[5/5] 检查服务状态..."
ssh "$SERVER" "systemctl status speed_test_server --no-pager"

echo ""
echo "=== 部署完成 ==="
echo ""
echo "服务管理命令:"
echo "  查看状态: ssh $SERVER 'systemctl status speed_test_server'"
echo "  查看日志: ssh $SERVER 'journalctl -u speed_test_server -f'"
echo "  停止服务: ssh $SERVER 'systemctl stop speed_test_server'"
echo "  重启服务: ssh $SERVER 'systemctl restart speed_test_server'"
echo ""
echo "本地测试命令:"
echo "  sudo ./target/release/speed_test client 38.175.192.236 9000 30 1400"
