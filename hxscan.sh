#!/bin/bash

# 定义函数以执行不同的操作
start_services() {
    echo "Starting services..."
    # 这里调用之前给出的启动脚本
    # 拉取最新镜像
    docker-compose pull

    # 停止旧容器（如果存在）
    docker-compose down

    # 启动 hxscan-tool 服务
    docker-compose up -d hxscan-tool

    # 等待一段时间，确保 hxscan-tool 有足够时间启动
    echo "Waiting for hxscan-tool to start..."
    sleep 20  # 可以根据实际情况调整等待时间

    # 启动 hxscan-app 服务
    docker-compose up -d hxscan-app

    # 显示运行中的容器
#    echo "Running containers:"
    #docker-compose ps

    # 获取本机的所有IPv4地址
    IPs=$(ip addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

    # 检查是否检测到至少一个IP地址
#    if [ -z "$IPs" ]; then
#        echo "Unable to determine the IP address. Using localhost as fallback."
#        IPs="localhost"
#    else
#         将检测到的每个IP地址打印出来
#        echo "Detected IP addresses:"
#        echo "$IPs"
#    fi

    # 使用for循环遍历每个IP地址并输出
    echo "Deployment completed. You can access the application at:"
    echo " - http://localhost:8000"
    for IP in $IPs; do
        # 输出每个IP的访问URL
        echo " - http://$IP:8000"
    done
}

stop_services() {
    echo "Stopping services..."
    docker-compose stop
}

restart_services() {
    echo "Restarting services..."
    docker-compose stop
    # 启动 hxscan-tool 服务
    docker-compose up -d hxscan-tool

    # 等待一段时间，确保 hxscan-tool 有足够时间启动
    echo "Waiting for hxscan-tool to start..."
    sleep 20  # 可以根据实际情况调整等待时间

    # 启动 hxscan-app 服务
    docker-compose up -d hxscan-app
}

down_services() {
    echo "Stopping and removing services..."
    docker-compose down
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