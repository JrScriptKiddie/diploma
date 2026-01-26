FROM scottyhardy/docker-remote-desktop:latest
#Ubuntu 

USER root

# 1. Добавляем 'nslcd' явно в список пакетов
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    nslcd \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils \
    nano \
    iputils-ping \
    net-tools \
    rsyslog \
    iproute2 \
    openssh-client \
    openssh-server \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Wazuh agent repo + install
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive WAZUH_MANAGER=srv_wazuh_manager apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

# 2. Настройка PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# 4. Настраиваем nsswitch
RUN sed -i 's/passwd:         files/passwd:         files ldap/' /etc/nsswitch.conf && \
    sed -i 's/group:          files/group:          files ldap/' /etc/nsswitch.conf && \
    sed -i 's/shadow:         files/shadow:         files ldap/' /etc/nsswitch.conf

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
