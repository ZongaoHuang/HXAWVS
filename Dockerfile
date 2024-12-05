# 使用官方Python运行时作为父镜像
FROM python:3.9

# 设置工作目录
WORKDIR /app

# 将当前目录内容复制到容器中的/app
COPY . /app

# 安装项目依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口8000供外部访问
EXPOSE 8000

# 持久化数据目录
VOLUME ["/app/dirscan_results", "/app/info_leak_results", "/app/port_scan_results", "/app/finger_print_results", "/app/media", "/app/db.sqlite3"]

# 运行Django服务器
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]