FROM osixia/openldap:latest

RUN sed -i 's@deb.debian.org/debian@archive.debian.org/debian@g; \
            s@security.debian.org/debian-security@archive.debian.org/debian-security@g; \
            /buster-backports/d' /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\n' >/etc/apt/apt.conf.d/99no-check-valid \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y nano iputils-ping net-tools rsyslog iproute2 curl \
 && rm -rf /var/lib/apt/lists/*


    # Custom entrypoint that runs an external ldap.sh (mounted via volume) before the default OpenLDAP startup
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]
