FROM ghcr.io/arkime/arkime/arkime:v5-latest

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nslcd \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils \
    nano \
    iputils-ping \
    net-tools \
    rsyslog \
    iproute2 \
    openssh-server \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]