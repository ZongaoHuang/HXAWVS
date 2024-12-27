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

    # 加载 Docker 镜像
    echo "Loading Docker images..."
    docker load -i hxscan-tool-v1.tar
    echo "hxscan-tool image loaded."
    docker load -i hxscan-app-v1.tar
    echo "hxscan-app image loaded."

    # 停止旧容器（如果存在）
    docker stop hxscan-tool-beta
    docker rm hxscan-tool-beta
    docker stop hxscan-app-beta
    docker rm hxscan-app-beta
    echo "Old containers stopped and removed."

    # 启动 hxscan-tool 服务
    $DOCKER_COMPOSE up -d hxscan-tool-beta
    echo "hxscan-tool service started."

    # 等待一段时间，确保 hxscan-tool 有足够时间启动
    echo "Waiting for hxscan-tool to start..."
    sleep 20  # 可以根据实际情况调整等待时间

    # 启动 hxscan-app 服务
    $DOCKER_COMPOSE up -d hxscan-app-beta
    echo "hxscan-app service started."
    $DOCKER_COMPOSE restart hxscan-app-beta

    echo "Initialization completed."

    # 获取IP地址
    IPs=$(get_ip_addresses)

    # 输出访问URL
    echo "You can access the application at:"
    echo " - http://localhost:8000"
    for IP in $IPs; do
        echo " - http://$IP:8000"
    done
}

start_services() {
    echo "Starting services..."

    # 启动 hxscan-tool 服务
    $DOCKER_COMPOSE start hxscan-tool-beta
    echo "hxscan-tool service started."

    # 等待一段时间，确保 hxscan-tool 有足够时间启动
    echo "Waiting for hxscan-tool to start..."
    sleep 20  # 可以根据实际情况调整等待时间

    # 启动 hxscan-app 服务
    $DOCKER_COMPOSE start hxscan-app-beta
    echo "hxscan-app service started."
    $DOCKER_COMPOSE restart hxscan-app-beta

    echo "All services started."

    # 获取IP地址
    IPs=$(get_ip_addresses)

    # 输出访问URL
    echo "You can access the application at:"
    echo " - http://localhost:8000"
    for IP in $IPs; do
        echo " - http://$IP:8000"
    done
}

# 新增的离线更新服务函数
update_services() {
    echo "Updating hxscan-app service..."

    # 停止 hxscan-app-beta 容器
    docker stop hxscan-app-beta
    docker rm hxscan-app-beta

    # 加载新的 hxscan-app 镜像
    docker load -i hxscan-app-new.tar
    echo "hxscan-app image updated."

    # 启动 hxscan-app 服务
    $DOCKER_COMPOSE up -d hxscan-app-beta
    echo "hxscan-app service restarted."

    # 获取IP地址
    IPs=$(get_ip_addresses)

    # 输出访问URL
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

# 根据用户选择执行相应的函数
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