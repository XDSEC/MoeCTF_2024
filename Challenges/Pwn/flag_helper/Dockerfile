FROM ubuntu:22.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd

RUN useradd -m ctf

WORKDIR /

RUN cp -R /usr/lib* /home/ctf

COPY ./build/ctf.xinetd /etc/xinetd.d/ctf
COPY ./build/start.sh /start.sh

RUN chown root:root /etc/xinetd.d/ctf && \
    chown root:root /start.sh && \
    chmod 400 /etc/xinetd.d/ctf && \
    chmod 500 /start.sh

COPY ./build/interface /
COPY ./build/flag /

RUN chown root:ctf /interface && \
    chmod 740 /flag

CMD ["/start.sh"]

EXPOSE 9999
