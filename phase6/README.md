# Phase 6 — Last-Mile Response Forgery

The resolver validates DNSSEC upstream, but the resolver→client hop carries no
proof of it. A stub resolver trusts whatever appears to come from its resolver —
including the `ad` ("authenticated data") flag, which an on-path attacker can set
at will. Here the adversary is moved to the **client subnet** (172.16.1.100) and
forges the reply where DNSSEC's guarantee has already run out.

Upstream (resolver + signed hierarchy) is the unchanged Phase 3 deployment. The
attack is run against two clients on the same host:
* **Client A** — an ordinary stub (`dig` / `curl` via the OS resolver). Lands on
  the rogue page.
* **Client B** — a locally-validating client (`delv` holding the root key as its
  own trust anchor). Detects the forgery and refuses it.

```
phase6/
  compose.yml                 attacker relocated to client-net 172.16.1.100 (project cs6008-p6)
  configs/ zones/             = Phase 3 signed, validating deployment
  scripts/
    sign-zones.sh             full signed chain (= Phase 3)
    divert-on.sh / off.sh     EDGE-router diversion of resolver->client replies
    build-attacker.sh         compile src/forge.c -> /usr/local/bin/forge
  src/forge.c, Makefile       C/libpcap last-mile forger (--relay / --forge)
  www/ rogue_www/             legitimate + defacement pages
```

---

## 0–1. Build, sign, deploy

```bash
sudo docker build -t cs6008-dns-lab:local -f ../common/Dockerfile ..   # once
mkdir -p evidence && chmod 777 evidence

sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash \
     cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh
```

## 2. Verify 6.2 — transparent relay: real page

```bash
sudo docker compose exec -T edge-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/forge --relay > /evidence/forge-relay.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig +dnssec example.com A +time=6 +tries=2 | tee evidence/p6-verify-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --max-time 5 http://example.com/ | tee evidence/p6-verify-curl.html
sudo docker compose exec -T attacker pkill -x forge || true
```
Expect `ad` + `172.16.1.20` + the real page (relay is transparent).

## 3. Attack 6.3 — forge the last-mile reply

```bash
IFACE=$(sudo docker compose exec -T edge-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.1\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d edge-router sh -c "exec tcpdump -i $IFACE -nn -s0 -U -Z root -w /evidence/p6-attack.pcap 'udp port 53' > /evidence/p6-tcpdump.log 2>&1"

sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/forge --forge > /evidence/forge-attack.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
```

**Client A — ordinary stub (expect rogue):**
```bash
sudo docker compose exec -T client dig example.com A +time=6 +tries=2 | tee evidence/p6-clientA-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 5 http://example.com/ | tee evidence/p6-clientA-curl.html
```
Expect `status: NOERROR`, `example.com. A 172.16.1.30`, **with the `ad` flag set**
(the attacker set it), and `curl` returns the rogue page.

**Client B — locally-validating with the root anchor (expect detection):**
```bash
sudo docker compose exec -T client delv @172.16.2.10 -a /lab/configs/trust-anchors.conf example.com A | tee evidence/p6-clientB-delv.txt
```
Expect delv to report the answer as **bogus / "no valid signature"** and refuse
to return an address — it validated the chain itself and the forged `A` has no
RRSIG.

```bash
sudo docker compose exec -T attacker pkill -x forge || true
sudo docker compose exec -T edge-router pkill -INT -x tcpdump || true
sudo docker compose exec -T edge-router /scripts/divert-off.sh
```

## Tear down
```bash
sudo docker compose down
```

---

## Report answers (6.4)

**Outcome for each client.** Client A (stub) accepts the forged reply and loads
the rogue page at 172.16.1.30. Client B (`delv` with the root trust anchor)
rejects it: having fetched the real DNSKEY/DS (which the attacker relays) it finds
the forged `A` carries no valid RRSIG and reports the answer bogus, returning no
address.

**DNSSEC validates upstream — why doesn't it stop this? Where validation happens
vs where trust is placed.** Validation happened at the *resolver*, one hop
upstream. The stub does not validate; it places its trust in the *channel* to the
resolver and in the `ad` flag the resolver sets. On the last mile that channel is
exactly what the on-path attacker controls, so the upstream validation result
never protects the stub — the attacker simply replaces the answer after the
resolver is out of the picture. DNSSEC protects data *in* the DNS; it does not
authenticate the resolver→stub link.

**What tells a stub its answer was validated (the `ad` flag), and why the
attacker can set it. What Client B does differently.** The only in-band signal is
the `ad` bit in the reply header. It is a single unauthenticated bit set by
whoever composes the packet — our forged reply sets it (`0x81 0xA0`), so the stub
believes a forged answer was "authenticated". Client B does not rely on that bit:
it performs validation *itself*, anchored on the root key it holds, so it checks
the signatures rather than trusting a flag — and the missing RRSIG gives the
forgery away. The lesson: last-mile integrity needs either local validation
(Client B) or an authenticated/encrypted channel to the resolver (Phase 7).

## Deliverables / evidence

| File | Shows |
|---|---|
| `evidence/p6-verify-dig.txt`, `p6-verify-curl.html` | 6.2 relay: `ad` + real page |
| `evidence/p6-clientA-dig.txt`, `p6-clientA-curl.html` | Client A: `172.16.1.30` (ad set) + rogue page |
| `evidence/p6-clientB-delv.txt` | Client B: forgery caught (bogus) |
| `evidence/forge-attack.log` | attacker `[FORGE]` activity |
| `evidence/p6-attack.pcap` | last-mile capture |
