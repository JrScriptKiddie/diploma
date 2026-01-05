FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      nginx \
      openssh-server \
      openssh-client \
      libnss-ldapd \
      libpam-ldapd \
      nslcd \
      nscd \
      ldap-utils \
      rsyslog \
      iproute2 \
      sudo \
      bash \
      curl \
      ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

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

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
