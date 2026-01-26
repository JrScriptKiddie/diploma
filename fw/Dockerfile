FROM alpine:latest

ENV TZ=Etc/UTC
RUN apk add --no-cache \
    shadow \
    nftables \
    iproute2 \
    iptables \
    openssh \
    openssh-server \
    sudo \
    bash \
    tcpdump \
    nano \
    rsyslog \
    nss-pam-ldapd \
    openldap-clients

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["/usr/local/bin/start.sh"]
