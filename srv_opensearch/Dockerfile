FROM opensearchproject/opensearch:latest

USER root 

RUN dnf install -y \
    nss-pam-ldapd \
    openldap-clients \
    nano \
    iputils \
    net-tools \
    rsyslog \
    iproute \
    openssh-server \
    sudo \
    && dnf clean all \
    && rm -rf /var/cache/dnf

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

ENTRYPOINT ["/usr/bin/start.sh"]
