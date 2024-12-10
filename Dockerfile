# 使用官方 Python 运行时作为父镜像
FROM python:3.9

# 设置工作目录
WORKDIR /app

# 安装必要的系统依赖
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    curl \
    gnupg2 \
    software-properties-common \
    && apt-get clean

# 安装 Google Chrome
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && apt-get clean

# 安装 ChromeDriver
RUN wget -q -O chromedriver-linux64.zip https://storage.googleapis.com/chrome-for-testing-public/131.0.6778.87/linux64/chromedriver-linux64.zip && \
    unzip chromedriver-linux64.zip -d /usr/local/bin/ && \
    mv /usr/local/bin/chromedriver-linux64/chromedriver /usr/local/bin/ && \
    chmod +x /usr/local/bin/chromedriver && \
    rm -r /usr/local/bin/chromedriver-linux64 && \
    rm chromedriver-linux64.zip

# 将当前目录内容复制到容器中的 /app
COPY . /app

# 安装项目依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口8000供外部访问
EXPOSE 8000

# 持久化数据目录
VOLUME ["/app/dirscan_results", "/app/info_leak_results", "/app/port_scan_results", "/app/finger_print_results", "/app/database"]

# 运行 Django 服务器
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]