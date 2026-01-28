FROM mcr.microsoft.com/dotnet/runtime:6.0

USER root

ENV DEBIAN_FRONTEND=noninteractive TZ=Europe/Moscow
RUN apt-get update

# Net tools, ssh, base utils
RUN apt-get install -y --no-install-recommends \
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
   cron   

# Passwords and politics
RUN apt-get install -y --no-install-recommends \
   nslcd \
   libnss-ldapd \
   libpam-ldapd \
   ldap-utils \
   libpam-pwquality \
   cracklib-runtime \    
   sudo

# Wazuh agent repo + install
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=srv_wazuh_manager apt-get install -y wazuh-agent

RUN apt install -y libcap2-bin

RUN rm -rf /var/lib/apt/lists/*

# 2. Настройка PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# ВАЖНО: nslcd запускается от пользователя nslcd, он должен уметь читать конфиг!
# Меняем владельца на root:nslcd и права на 640
RUN chown root:nslcd /etc/nslcd.conf && chmod 640 /etc/nslcd.conf

# 4. Настраиваем nsswitch
RUN sed -i 's/passwd:         files/passwd:         files ldap/' /etc/nsswitch.conf && \
    sed -i 's/group:          files/group:          files ldap/' /etc/nsswitch.conf && \
    sed -i 's/shadow:         files/shadow:         files ldap/' /etc/nsswitch.conf

RUN groupadd -g 31337 polarproxy && \
    useradd -m -u 31337 -g polarproxy polarproxy && \
    mkdir -p /var/log/PolarProxy /opt/polarproxy && \
    chown polarproxy:polarproxy /var/log/PolarProxy && \
    apt-get update && apt-get install -y curl && curl -s https://www.netresec.com/?download=PolarProxy | tar -xzf - -C /opt/polarproxy

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

WORKDIR /opt/polarproxy/

ENTRYPOINT ["/usr/bin/start.sh"]
