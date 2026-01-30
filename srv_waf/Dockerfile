FROM owasp/modsecurity-crs:nginx
# Debian

USER root

# Optional: add troubleshooting tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nano \
    iputils-ping \
    net-tools \
    rsyslog \
    iproute2 \
    nslcd \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils \
    sudo \
    cron \
    openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 2. Настройка PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# 3. Копируем конфиги
COPY nslcd.conf /etc/nslcd.conf



# 4. Настраиваем nsswitch
RUN sed -i 's/passwd:         files/passwd:         files ldap/' /etc/nsswitch.conf && \
    sed -i 's/group:          files/group:          files ldap/' /etc/nsswitch.conf && \
    sed -i 's/shadow:         files/shadow:         files ldap/' /etc/nsswitch.conf
        
COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

COPY add-global-rate-limit.sh /usr/local/bin/add-global-rate-limit.sh
RUN chmod +x /usr/local/bin/add-global-rate-limit.sh

ENTRYPOINT ["/usr/bin/start.sh"]

CMD ["nginx", "-g", "daemon off;"]
