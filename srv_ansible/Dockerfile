FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Moscow

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gnupg \
    nano \
    iputils-ping \
    net-tools \
    dnsutils \
    rsyslog \
    iproute2 \
    openssh-client \
    openssh-server \
    curl \
    cron \
    nslcd \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils \
    libpam-pwquality \
    cracklib-runtime \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Wazuh agent repo + install
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=srv_wazuh_manager apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

# Ansible-specific packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ansible \
    sshpass \
    python3 \
    python3-pip

RUN rm -rf /var/lib/apt/lists/*

# PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# NSS
RUN sed -i 's/passwd:         files/passwd:         files ldap/' /etc/nsswitch.conf && \
    sed -i 's/group:          files/group:          files ldap/' /etc/nsswitch.conf && \
    sed -i 's/shadow:         files/shadow:         files ldap/' /etc/nsswitch.conf

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

WORKDIR /workspace

CMD ["/usr/local/bin/start.sh"]
