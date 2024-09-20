#!/bin/bash

# 定义函数以执行不同的操作
start_services() {
    echo "Starting services..."
    # 停止旧容器（如果存在）
    docker-compose down

    # 启动 hxscan-tool 服务
    docker-compose up -d hxscan-tool

    # 等待一段时间，确保 hxscan-tool 有足够时间启动
    echo "Waiting for hxscan-tool to start..."
    sleep 20  # 可以根据实际情况调整等待时间

    # 启动 hxscan-app 服务
    docker-compose up -d hxscan-app

    # 获取本机的所有IPv4地址
    IPs=\$(ip addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

    # 输出访问URL
    echo "Deployment completed. You can access the application at:"
    echo " - http://localhost:8000"
    for IP in \$IPs; do
        echo " - http://\$IP:8000"
    done
}

stop_services() {
    echo "Stopping services..."
    docker-compose stop
}

restart_services() {
    echo "Restarting services..."
    docker-compose restart hxscan-tool
    echo "Waiting for hxscan-tool to restart..."
    sleep 20
    docker-compose restart hxscan-app
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
case "\$choice" in
    1) start_services ;;
    2) stop_services ;;
    3) restart_services ;;
    4) down_services ;;
    *) echo "Invalid choice." ;;
esac

echo "Operation completed."