FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
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

# Nftables + Suricata
RUN apt install -y --no-install-recommends \
    nftables \
    iptables \
    tcpdump \
    suricata \
    suricata-update \
    ethtool

RUN suricata-update

RUN rm -rf /var/lib/apt/lists/*

# 2. Настройка PAM (mkhomedir)
RUN echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session

# ВАЖНО: nslcd запускается от пользователя nslcd, он должен уметь читать конфиг!
# Меняем владельца на root:nslcd и права на 640
RUN chown root:nslcd /etc/nslcd.conf && chmod 640 /etc/nslcd.conf

COPY suricata.yaml /etc/suricata/suricata.yaml.template

# 4. Настраиваем nsswitch
RUN sed -i 's/passwd:         files/passwd:         files ldap/' /etc/nsswitch.conf && \
    sed -i 's/group:          files/group:          files ldap/' /etc/nsswitch.conf && \
    sed -i 's/shadow:         files/shadow:         files ldap/' /etc/nsswitch.conf

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]
