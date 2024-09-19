#!/bin/bash

# 拉取最新镜像
docker-compose pull

# 停止旧容器（如果存在）
docker-compose down

# 启动 hxscan-tool 服务
docker-compose up -d hxscan-tool

# 等待一段时间，确保 hxscan-tool 有足够时间启动
echo "Waiting for hxscan-tool to start..."
sleep 60  # 可以根据实际情况调整等待时间

# 启动 hxscan-app 服务
docker-compose up -d hxscan-app

# 显示运行中的容器
echo "Running containers:"
docker-compose ps

echo "Deployment completed. You can access the application at http://localhost:8000"