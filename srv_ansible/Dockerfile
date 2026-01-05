FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ansible \
    smbclient \
    openssh-server \
    sshpass \
    python3 \
    python3-pip \
    cifs-utils \
    cron \
    iputils-ping \
    sudo \
    iproute2 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

EXPOSE 22

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

WORKDIR /workspace

CMD ["/usr/local/bin/start.sh"]
