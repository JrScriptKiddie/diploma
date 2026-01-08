FROM wgportal/wg-portal:latest

RUN apk add --no-cache \
    linux-pam \
    openssh \
    nano \
    net-tools \
    sudo \
    rsyslog

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
