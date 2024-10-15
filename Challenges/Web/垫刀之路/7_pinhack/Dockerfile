FROM python:3.10.14-alpine
WORKDIR /app

RUN pip install flask -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN mkdir /app/templates
COPY webapp/ /app/
COPY fake_flag /flag


EXPOSE 80

ENTRYPOINT [ "sh", "start.sh" ]
