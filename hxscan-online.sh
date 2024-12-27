#!/bin/bash

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
init_services() {
    echo "Initializing services..."

    # 拉取最新的 Docker 镜像
    echo "Pulling Docker images..."
    docker pull sakura501/hxscan-tool:v1
    echo "hxscan-tool image pulled."
    docker pull snow7/hxscan-app:v1
    echo "hxscan-app image pulled."

    # 停止旧容器（如果存在）
    docker stop hxscan-tool-beta
    docker rm hxscan-tool-beta
    docker stop hxscan-app-beta
    docker rm hxscan-app-beta
    echo "Old containers stopped and removed."

    # 启动服务
    $DOCKER_COMPOSE up -d hxscan-tool-beta
    echo "hxscan-tool service started."

    echo "Waiting for hxscan-tool to start..."
    sleep 20

    $DOCKER_COMPOSE up -d hxscan-app-beta
    echo "hxscan-app service started."
    $DOCKER_COMPOSE restart hxscan-app-beta

    echo "Initialization completed."

    # 获取IP地址
    IPs=$(get_ip_addresses)
    echo "You can access the application at:"
    echo " - http://localhost:8000"
    for IP in $IPs; do
        echo " - http://$IP:8000"
    done
}

# 新增的更新服务函数
update_services() {
    echo "Updating hxscan-app service..."

    # 更新 hxscan-app 容器
    $DOCKER_COMPOSE pull hxscan-app-beta
    $DOCKER_COMPOSE up -d hxscan-app-beta

    echo "hxscan-app service updated."
}

# ... 其他函数保持不变 ...
start_services() {
    echo "Starting services..."
    $DOCKER_COMPOSE start hxscan-tool-beta
    echo "hxscan-tool service started."
    echo "Waiting for hxscan-tool to start..."
    sleep 20
    $DOCKER_COMPOSE start hxscan-app-beta
    echo "hxscan-app service started."
    $DOCKER_COMPOSE restart hxscan-app-beta
    echo "All services started."

    # 获取IP地址
    IPs=$(get_ip_addresses)
    echo "You can access the application at:"
    echo " - http://localhost:8000"
    for IP in $IPs; do
        echo " - http://$IP:8000"
    done
}

stop_services() {
    echo "Stopping services..."
    $DOCKER_COMPOSE stop
    echo "All services stopped."
}

restart_services() {
    echo "Restarting services..."
    $DOCKER_COMPOSE restart hxscan-tool-beta
    echo "hxscan-tool restarted."
    echo "Waiting for hxscan-tool to restart..."
    sleep 20
    $DOCKER_COMPOSE restart hxscan-app-beta
    echo "hxscan-app restarted."
    echo "All services restarted."
}

down_services() {
    echo "Stopping and removing services..."
    $DOCKER_COMPOSE down
    echo "All services stopped and removed."
}

# 显示菜单并获取用户选择
echo "Please choose an option:"
echo "1) Initialize services"
echo "2) Start services"
echo "3) Stop services"
echo "4) Restart services"
echo "5) Stop and remove services"
echo "6) update app services"
read -p "Enter choice [1-6]: " choice

case "$choice" in
    1) init_services ;;
    2) start_services ;;
    3) stop_services ;;
    4) restart_services ;;
    5) down_services ;;
    6) update_services ;;
    *) echo "Invalid choice." ;;
esac

echo "Operation completed."