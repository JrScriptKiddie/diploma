FROM ghcr.io/perber/leafwiki:latest

# Alpine-based install
RUN apk update \
 && apk add --no-cache \
    iputils \
    iproute2 \
    ca-certificates

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]
