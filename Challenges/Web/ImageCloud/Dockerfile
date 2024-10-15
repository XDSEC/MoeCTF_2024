# 使用官方 Python 运行时作为基础镜像
FROM python:3.10-alpine

# 作者信息
LABEL maintainer="xt"

# 设置工作目录
WORKDIR /app

# 安装 Python 依赖
RUN pip install --no-cache-dir flask requests Pillow

# 复制应用的代码到容器
COPY . .

# 暴露端口
EXPOSE 5000

# 运行 Flask 应用
CMD ["sh", "-c", "python init.py && python app.py & python app2.py"]
