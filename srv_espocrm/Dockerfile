FROM espocrm/espocrm:latest

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY start.sh /usr/bin/start.sh
RUN chmod +x /usr/bin/start.sh

RUN chown -R www-data:www-data /var/www/

ENTRYPOINT ["/usr/bin/start.sh"]
