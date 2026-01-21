FROM mcr.microsoft.com/dotnet/runtime:6.0

USER root

RUN apt update && apt install -y \
    nslcd \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils \
    libcap2-bin \
    nano \
    iputils-ping \
    net-tools \
    rsyslog \
    iproute2 \
    openssh-server \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 31337 polarproxy && \
    useradd -m -u 31337 -g polarproxy polarproxy && \
    mkdir -p /var/log/PolarProxy /opt/polarproxy && \
    chown polarproxy:polarproxy /var/log/PolarProxy && \
    apt-get update && apt-get install -y curl && curl -s https://www.netresec.com/?download=PolarProxy | tar -xzf - -C /opt/polarproxy

VOLUME ["/var/log/PolarProxy/", "/home/polarproxy/"]

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

WORKDIR /opt/polarproxy/

ENTRYPOINT ["/usr/bin/start.sh"]
