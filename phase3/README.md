# Phase 3 — DNSSEC Chain of Trust

## Architecture & Signing
Authoritative zones are signed using ECDSA P-256 with SHA-256 (Algorithm 13):
- Root (`.`) signed with KSK and ZSK.
- `com.` signed with KSK and ZSK, with its DS record published in the Root zone.
- `example.com.` signed with KSK and ZSK, with its DS record published in `com.`.
- Resolver validates DNSSEC (`dnssec-validation yes;`) anchored to the Root KSK in `configs/trust-anchors.conf`.

## Zone Signing
Zones and keys are generated using the signing script:
```bash
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones.sh
```

## Build and Deployment
```bash
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh
```

## Verification 3.2 — Healthy DNSSEC Validation
```bash
sudo docker compose exec -T client dig +dnssec example.com A +time=3 +tries=1
sudo docker compose exec -T client delv @172.16.2.10 -a /lab/configs/trust-anchors.conf example.com A
```
`dig` returns `flags: qr rd ra ad` with valid `RRSIG`, and `delv` returns `; fully validated`.

## Attack 3.3 — Repeat Phase 2 Attack against Validating Resolver
```bash
sudo docker compose exec -d core-router sh -c 'exec tcpdump -i eth1 -nn -s 0 -U -Z root -w /evidence/p3-attack.pcap "udp port 53" > /evidence/p3-tcpdump.log 2>&1'
sudo docker compose exec -T core-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/interceptor --forge > /evidence/interceptor-p3.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush

sudo docker compose exec -T client dig example.com A +time=6 +tries=2
sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 5 http://example.com/

sudo docker compose exec -T attacker pkill -x interceptor || true
sudo docker compose exec -T core-router pkill -INT -x tcpdump || true
sudo docker compose exec -T core-router /scripts/divert-off.sh
```
The forged response is rejected by the validating resolver (yielding SERVFAIL / resolution failure). `curl` reports `Could not resolve host: example.com`, preventing redirection to the rogue web server.
