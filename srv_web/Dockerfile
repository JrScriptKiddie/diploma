FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      nginx \
      openssh-server \
      openssh-client \
      sssd \
      sssd-tools \
      sssd-ldap \
      libnss-sss \
      libpam-sss \
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
# 4. Настраиваем nsswitch
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]

