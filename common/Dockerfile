# common/Dockerfile
# One image used by every container in every phase. BIND 9.20, DNS tools
# (dig/delv/kdig), capture (tshark/tcpdump), iproute2, a C toolchain + libpcap,
# OpenSSL (Phase 7 PKI), busybox (tiny web server), and the ROLE dispatcher.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    echo "deb http://deb.debian.org/debian bookworm-backports main" \
        > /etc/apt/sources.list.d/backports.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bind9/bookworm-backports \
        bind9-utils/bookworm-backports \
        bind9-dnsutils/bookworm-backports \
        bind9-host/bookworm-backports \
        knot-dnsutils dnsutils iproute2 iptables iputils-ping \
        tcpdump tshark curl ca-certificates openssl \
        gcc make libpcap-dev libpcap0.8 \
        procps net-tools busybox python3 vim-tiny less; \
    rm -rf /var/lib/apt/lists/*

# Fail the build (not a later container boot) if backports ever serves a
# different major/minor than what this lab was built and tested against.
RUN named -v | grep -E 'BIND 9\.20\.'

RUN mkdir -p /var/cache/bind /var/log/named /run/named && \
    chown -R bind:bind /var/cache/bind /var/log/named /run/named
RUN mkdir -p /opt/attack

# Bake in the per-role start script as the image entrypoint, so every
# container role-dispatches on boot (reads $ROLE, installs routes, execs named
# / busybox httpd / idles). Build context must be the repo root.
COPY common/node-start.sh /usr/local/bin/node-start.sh
RUN chmod +x /usr/local/bin/node-start.sh
ENTRYPOINT ["/usr/local/bin/node-start.sh"]
