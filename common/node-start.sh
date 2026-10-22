#!/bin/sh
set -eu

: "${ROLE:?ROLE must be set}"

# Do not allow Docker's host gateway to become an alternate route.
while ip -4 route del default 2>/dev/null; do
    :
done

case "$ROLE" in
    client)
        ip route replace 172.16.2.0/24 via 172.16.1.2
        printf 'nameserver 172.16.2.10\noptions timeout:2 attempts:1\n' \
            > /etc/resolv.conf
        ;;

    resolver)
        ip route replace 172.16.1.0/24 via 172.16.2.2
        ip route replace 172.16.3.0/24 via 172.16.2.3
        ;;

    root-ns|tld-ns|domain-ns)
        ip route replace 172.16.2.0/24 via 172.16.3.3
        ;;

    edge-router|core-router|webserver)
        ;;

    *)
        echo "Unknown ROLE: $ROLE" >&2
        exit 1
        ;;
esac

echo "=== $ROLE: IPv4 addresses ==="
ip -4 -brief address

echo "=== $ROLE: routes ==="
ip -4 route

echo "=== $ROLE: forwarding ==="
cat /proc/sys/net/ipv4/ip_forward

case "$ROLE" in
    resolver|root-ns|tld-ns|domain-ns)
        mkdir -p /run/named /var/cache/bind

        # A fresh local control key is generated at runtime.
        rndc-confgen -a -c /run/named/rndc.key

        chown -R bind:bind /run/named /var/cache/bind

        named-checkconf -z /lab/configs/"$ROLE".conf

        exec named -4 -g -u bind -n 1 \
            -c /lab/configs/"$ROLE".conf
        ;;

    webserver)
        exec busybox httpd -f -p 80 -h /www
        ;;

    *)
        exec sleep infinity
        ;;
esac
