#!/bin/bash

SERVER="root@38.175.192.236"
SERVER_IP="38.175.192.236"
PORT="9000"

show_help() {
    cat << EOF
Speed Test 管理脚本

用法: $0 <命令>

命令:
  status    - 查看服务端状态
  logs      - 查看服务端日志 (实时)
  stop      - 停止服务端
  start     - 启动服务端
  restart   - 重启服务端
  test      - 运行本地客户端测速 (30秒)
  deploy    - 重新部署服务端

示例:
  $0 status
  $0 test
  $0 logs
EOF
}

case "$1" in
    status)
        echo "=== 服务端状态 ==="
        ssh "$SERVER" "systemctl status speed_test_server --no-pager"
        ;;

    logs)
        echo "=== 服务端日志 (Ctrl+C 退出) ==="
        ssh "$SERVER" "journalctl -u speed_test_server -f"
        ;;

    stop)
        echo "=== 停止服务端 ==="
        ssh "$SERVER" "systemctl stop speed_test_server"
        echo "服务已停止"
        ;;

    start)
        echo "=== 启动服务端 ==="
        ssh "$SERVER" "systemctl start speed_test_server"
        sleep 2
        ssh "$SERVER" "systemctl status speed_test_server --no-pager"
        ;;

    restart)
        echo "=== 重启服务端 ==="
        ssh "$SERVER" "systemctl restart speed_test_server"
        sleep 2
        ssh "$SERVER" "systemctl status speed_test_server --no-pager"
        ;;

    test)
        echo "=== 运行客户端测速 (30秒) ==="
        sudo ./target/release/speed_test client "$SERVER_IP" "$PORT" 30 1400
        ;;

    deploy)
        echo "=== 重新部署服务端 ==="
        ./deploy_speed_test.sh
        ;;

    *)
        show_help
        exit 1
        ;;
esac
