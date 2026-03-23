FROM alpine:3.20

RUN apk add --no-cache \
    openvpn \
    bash \
    curl \
    python3 \
    py3-pip \
    git \
    build-base \
    && git clone https://github.com/rofl0r/microsocks.git /tmp/microsocks \
    && cd /tmp/microsocks \
    && make \
    && cp /tmp/microsocks/microsocks /usr/local/bin/microsocks \
    && rm -rf /tmp/microsocks \
    && apk del git build-base

RUN pip3 install --no-cache-dir --break-system-packages flask

COPY dashboard/ /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1080 8080

ENTRYPOINT ["/entrypoint.sh"]
