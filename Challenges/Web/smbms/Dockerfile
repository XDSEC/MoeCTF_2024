# FROM mariadb:latest
# FROM alpine:latest
FROM ubuntu:latest

COPY ./src /app
# COPY ./my.cnf /etc/my.cnf

# RUN apk update && apk add openjdk8 mysql mysql-client 
RUN apt-get update -y && apt-get install openjdk-8-jdk mariadb-client mariadb-server -y 

# ENV MARIADB_ROOT_PASSWORD=root
# CMD [ "chmod","+x","/app/docker-entrypoint.sh" ] 
ENTRYPOINT ["sh", "/app/docker-entrypoint.sh"]

EXPOSE 8080
