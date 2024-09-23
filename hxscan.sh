#!/bin/bash

# 确保脚本在正确的目录中运行
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# 定义项目名称
PROJECT_NAME="hxscan"

# 定义 docker-compose 命令，包含项目名称
DOCKER_COMPOSE="docker-compose -p $PROJECT_NAME"

# 函数：获取IP地址
get_ip_addresses() {
    if command -v ip >/dev/null 2>&1; then
        ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1'
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'
    else
        echo "localhost"
    fi
}

# 定义函数以执行不同的操作
start_services() {
    echo "Starting services..."
    # 拉取最新镜像
    $DOCKER_COMPOSE pull

    # 停止旧容器（如果存在）
    $DOCKER_COMPOSE down

    # 启动 hxscan-tool 服务
    $DOCKER_COMPOSE up -d hxscan-tool

    # 等待一段时间，确保 hxscan-tool 有足够时间启动
    echo "Waiting for hxscan-tool to start..."
    sleep 20  # 可以根据实际情况调整等待时间

    # 启动 hxscan-app 服务
    $DOCKER_COMPOSE up -d hxscan-app

    # 获取IP地址
    IPs=$(get_ip_addresses)

    # 输出访问URL
    echo "Deployment completed. You can access the application at:"
    echo " - http://localhost:8000"
    for IP in $IPs; do
        echo " - http://$IP:8000"
    done
}

stop_services() {
    echo "Stopping services..."
    $DOCKER_COMPOSE stop
}

restart_services() {
    echo "Restarting services..."
    $DOCKER_COMPOSE restart hxscan-tool
    echo "Waiting for hxscan-tool to restart..."
    sleep 20
    $DOCKER_COMPOSE restart hxscan-app
}

down_services() {
    echo "Stopping and removing services..."
    $DOCKER_COMPOSE down
}

# 显示菜单并获取用户选择
echo "Please choose an option:"
echo "1) Start services"
echo "2) Stop services"
echo "3) Restart services"
echo "4) Stop and remove services"
read -p "Enter choice [1-4]: " choice

# 根据用户选择执行相应的函数
case "$choice" in
    1) start_services ;;
    2) stop_services ;;
    3) restart_services ;;
    4) down_services ;;
    *) echo "Invalid choice." ;;
esac

echo "Operation completed."