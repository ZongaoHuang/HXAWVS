#!/bin/bash

# 拉取最新镜像
docker-compose pull

# 停止旧容器（如果存在）
docker-compose down

# 启动 hxscan-tool 服务
docker-compose up -d hxscan-tool

# 等待 hxscan-tool 服务健康检查通过
echo "Waiting for hxscan-tool to be ready..."
while ! docker-compose ps | grep hxscan-tool | grep -q "(healthy)"; do
    sleep 5
done
echo "hxscan-tool is ready."

# 启动 hxscan-app 服务
docker-compose up -d hxscan-app

# 显示运行中的容器
echo "Running containers:"
docker-compose ps

echo "Deployment completed. You can access the application at http://localhost:8000"