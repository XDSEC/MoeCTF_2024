FROM python:3.10.14-alpine

WORKDIR /app

RUN pip install flask -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN mkdir /app/templates 
COPY templates /app/templates
COPY static /app/static
COPY app.py /app/

EXPOSE 80

ENTRYPOINT [ "python", "app.py" ]
