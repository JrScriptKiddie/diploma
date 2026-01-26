FROM scottyhardy/docker-remote-desktop:latest
# Ubuntu

USER root

# 1. Добавляем 'nslcd' явно в список пакетов
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nslcd \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils \
    libpam-pwquality \
    nano \
    iputils-ping \
    net-tools \
    rsyslog \
    cron \
    iproute2 \
    remmina \
    curl \
    gnupg \
    apt-transport-https \
    dnsutils \
    openssh-client \
    openssh-server \
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

# 3. Копируем конфиги
COPY nslcd.conf /etc/nslcd.conf

# ВАЖНО: nslcd запускается от пользователя nslcd, он должен уметь читать конфиг!
# Меняем владельца на root:nslcd и права на 640
RUN chown root:nslcd /etc/nslcd.conf && chmod 640 /etc/nslcd.conf

# 4. Настраиваем nsswitch
RUN sed -i 's/passwd:         files/passwd:         files ldap/' /etc/nsswitch.conf && \
    sed -i 's/group:          files/group:          files ldap/' /etc/nsswitch.conf && \
    sed -i 's/shadow:         files/shadow:         files ldap/' /etc/nsswitch.conf

COPY /start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
