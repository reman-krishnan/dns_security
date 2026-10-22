FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bind9 \
       bind9-utils \
       bind9-dnsutils \
       knot-dnsutils \
       iproute2 \
       procps \
       tcpdump \
       tshark \
       curl \
       openssl \
       ca-certificates \
       busybox \
       build-essential \
       libpcap-dev \
    && named -v \
    && named -v | grep -Eq '^BIND 9\.20\.' \
    && rm -rf /var/lib/apt/lists/*

COPY node-start.sh /usr/local/sbin/node-start.sh

RUN chmod 0755 /usr/local/sbin/node-start.sh

ENTRYPOINT ["/usr/local/sbin/node-start.sh"]
