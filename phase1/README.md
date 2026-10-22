# Phase 1 — Building the DNS Hierarchy

## Requirements

- Docker Engine and Docker Compose
- Internet access during the image build to fetch Debian packages
- The project-level `common/Dockerfile` and `common/node-start.sh`

## Build and deploy

From this directory:

    sudo docker compose config --quiet
    sudo docker compose build client
    sudo docker compose up -d --no-build
    sudo docker compose ps -a

The image build checks that the installed BIND version is 9.20.x.
The Compose deployment creates three internal networks and eight
containers. No ports are published to the host.

## Verify BIND and routing

    for node in resolver root-ns tld-ns domain-ns; do
        sudo docker compose exec -T "$node" named -v
    done

    sudo docker compose exec -T resolver ip route get 172.16.3.10

The resolver's route to the root nameserver must use next hop
172.16.2.3. Check all node routes and forwarding settings with:

    sudo docker compose exec -T client ip -4 route
    sudo docker compose exec -T resolver ip -4 route
    sudo docker compose exec -T root-ns ip -4 route
    sudo docker compose exec -T tld-ns ip -4 route
    sudo docker compose exec -T domain-ns ip -4 route
    sudo docker compose exec -T edge-router ip -4 route
    sudo docker compose exec -T core-router ip -4 route

    sudo docker compose exec -T client cat /proc/sys/net/ipv4/ip_forward
    sudo docker compose exec -T resolver cat /proc/sys/net/ipv4/ip_forward
    sudo docker compose exec -T edge-router cat /proc/sys/net/ipv4/ip_forward
    sudo docker compose exec -T core-router cat /proc/sys/net/ipv4/ip_forward

Only the routers should have IPv4 forwarding enabled.

## Verify DNS and HTTP

    sudo docker compose exec -T client dig example.com A +time=3 +tries=1
    sudo docker compose exec -T client dig www.example.com A +time=3 +tries=1

Both names should resolve to 172.16.1.20.

    sudo docker compose exec -T client \
        curl --noproxy '*' --fail --show-error --max-time 10 \
        http://example.com/

The fetched page should identify itself as the legitimate example.com
website and the connection should be to 172.16.1.20.

## Verify isolation

    sudo docker compose exec -T client \
        dig @172.16.3.10 example.com A +time=2 +tries=1

This direct client-to-root query should fail because the client has
no route to the authoritative subnet.

## Capture the referral chain

Start a capture on the core router's resolver-facing interface.
Trigger a fresh lookup after flushing the resolver cache, then stop
the capture:

    sudo docker compose exec -d core-router sh -c '
        iface=$(ip -o -4 address show |
            awk '\''$4 == "172.16.2.3/24" { print $2 }'\'')
        test -n "$iface" || exit 1
        exec tcpdump -i "$iface" -nn -s 0 -U -Z root \
            -w /evidence/core-dns.pcap \
            "udp port 53 or tcp port 53" \
            > /evidence/tcpdump.log 2>&1
    '

    sleep 2
    sudo docker compose exec -T resolver \
        rndc -k /run/named/rndc.key -s 127.0.0.1 flush
    sudo docker compose exec -T client \
        dig example.com A +time=3 +tries=1
    sleep 2
    sudo docker compose exec -T core-router pkill -INT -x tcpdump
    sleep 2

Generate the packet summary and detailed decode:

    sudo docker compose exec -T core-router \
        tshark -r /evidence/core-dns.pcap -Y dns

    sudo docker compose exec -T core-router \
        tshark -r /evidence/core-dns.pcap -Y dns -V \
        > evidence/dns-packet-details.txt

Frame numbers and transaction IDs are capture-specific. See
evidence/capture-annotations.md for annotations of the submitted
capture; regenerate those annotations if the capture changes.

## Evidence

Evidence captured from this run is stored in `evidence/`, including
DNS answers, the HTTP fetch, routes and forwarding state, the direct
query failure, packet capture, packet summary, and capture annotations.

## Stop the deployment

    sudo docker compose down
