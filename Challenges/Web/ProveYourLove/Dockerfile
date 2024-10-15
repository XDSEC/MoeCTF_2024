FROM python:3.11-alpine

WORKDIR /app

COPY . /app
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

RUN pip install --no-cache-dir flask

RUN python init_db.py

EXPOSE 5000

CMD ["/entrypoint.sh"]
