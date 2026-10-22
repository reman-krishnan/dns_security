# Phase 7 — Encrypting the Last Mile (DoT / DoH)

Phase 6 showed the resolver→client hop is forgeable. Phase 7 authenticates and
encrypts that hop with a private CA and DNS-over-TLS / DNS-over-HTTPS, then
mounts three attacks against two kinds of client and accounts for all six
results.

* Private CA (`scripts/make-pki.sh`) installed in the client's trust store.
* Resolver reached **by name** `resolver.cs6008.local` (client `extra_hosts`),
  cert SAN = that name, **no IP SAN** — the client validates the cert against the
  hostname it connected to.
* Resolver speaks **DoT (853)** and **DoH (443)** from the lab PKI (`configs/resolver.conf`).
* Two clients: **strict** (`resolve-strict.sh`, DoT only, no cleartext fallback)
  and **permissive** (`resolve-permissive.sh`, DoT then cleartext fallback).

Upstream (resolver→auth, signed hierarchy) is the Phase 3 deployment; the
attacker is on the client subnet (172.16.1.100) as in Phase 6. The C/libpcap
tool `src/mitm.c` relays the diverted last-mile traffic, forges the cleartext
fallback, and can corrupt the DoT stream. Transport-layer attacks (rogue cert,
port block) run on the edge-router with `openssl`/`iptables`.

```
phase7/
  compose.yml                 attacker on client-net; PKI mounted; resolver.cs6008.local via extra_hosts
  configs/resolver.conf       validating resolver + DoT(853) + DoH(443) via lab PKI
  scripts/
    make-pki.sh               private CA, resolver cert (SAN), rogue cert
    sign-zones.sh             signed hierarchy (= Phase 3)
    resolve-strict.sh         Client (refuses cleartext)
    resolve-permissive.sh     Client (permits cleartext fallback)
    divert-on.sh / off.sh     edge-router last-mile diversion
    attack-block-on/off.sh    (iii) deny transport: block TCP 853/443
    attack-rogue-on/off.sh    (ii) rogue cert: REDIRECT 853 -> openssl s_server (rogue)
    build-attacker.sh         compile src/mitm.c
  src/mitm.c, Makefile        C/libpcap: --forge-cleartext / --break-dot
```

---

## 0–1. Build PKI, sign, deploy

```bash
sudo docker build -t cs6008-dns-lab:local -f ../common/Dockerfile ..   # once
mkdir -p evidence && chmod 777 evidence

sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/make-pki.sh
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh
```

## 2. Verify 7.2 — encrypted resolution, cert validates, no cleartext

No attacker on-path (diversion off). Capture the client's last mile on the
edge-router while the strict client resolves over DoT:

```bash
IFACE=$(sudo docker compose exec -T edge-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.1\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d edge-router sh -c "exec tcpdump -i $IFACE -nn -s0 -U -Z root -w /evidence/p7-verify.pcap 'host 172.16.1.10 and (port 53 or port 853 or port 443)' > /evidence/p7-verify-tcpdump.log 2>&1"

sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client /scripts/resolve-strict.sh | tee evidence/p7-verify-strict.txt

sudo docker compose exec -T edge-router pkill -INT -x tcpdump || true
sudo docker compose exec -T edge-router sh -c "tcpdump -nn -r /evidence/p7-verify.pcap 'port 53' | head" | tee evidence/p7-verify-no-cleartext.txt
```
Expect: the strict client returns `172.16.1.20` (cert validated cleanly, upstream
DNSSEC `ad` still holds), and the port-53 read of the client's last mile is
**empty** — the lookup went over TCP 853 only.

## 3. Attacks 7.3 — three attempts × two clients

For every attempt, the permissive client's cleartext fallback is hijacked by the
Phase-6-style forger, so first put the diversion + forger in place:

```bash
sudo docker compose exec -T edge-router /scripts/divert-on.sh
# mitm relays the DoT stream transparently and forges only the UDP/53 fallback
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/mitm --forge-cleartext > /evidence/mitm.log 2>&1'
```

### (i) Alter the answer in transit
Add DoT corruption (restart mitm with both flags):
```bash
sudo docker compose exec -T attacker pkill -x mitm || true
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/mitm --forge-cleartext --break-dot > /evidence/mitm-i.log 2>&1'
sudo docker compose exec -T client /scripts/resolve-strict.sh      | tee evidence/p7-i-strict.txt
sudo docker compose exec -T client /scripts/resolve-permissive.sh  | tee evidence/p7-i-permissive.txt
```
- **strict:** TLS record MAC fails → session torn down → **no answer** (does not land).
- **permissive:** DoT fails → cleartext fallback → forged → **172.16.1.30 (lands)**.

Reset mitm to forge-only for the next attempts:
```bash
sudo docker compose exec -T attacker pkill -x mitm || true
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/mitm --forge-cleartext > /evidence/mitm.log 2>&1'
```

### (ii) Impersonate the resolver with a rogue certificate
```bash
sudo docker compose exec -T edge-router /scripts/attack-rogue-on.sh
sudo docker compose exec -T client /scripts/resolve-strict.sh      | tee evidence/p7-ii-strict.txt
sudo docker compose exec -T client /scripts/resolve-permissive.sh  | tee evidence/p7-ii-permissive.txt
sudo docker compose exec -T edge-router /scripts/attack-rogue-off.sh
```
- **strict:** rogue cert not signed by the lab CA → validation fails → **no answer**.
- **permissive:** DoT cert fails → fallback → forged → **172.16.1.30 (lands)**.

### (iii) Deny the encrypted transport (force cleartext)
```bash
sudo docker compose exec -T edge-router /scripts/attack-block-on.sh
sudo docker compose exec -T client /scripts/resolve-strict.sh      | tee evidence/p7-iii-strict.txt
sudo docker compose exec -T client /scripts/resolve-permissive.sh  | tee evidence/p7-iii-permissive.txt
sudo docker compose exec -T edge-router /scripts/attack-block-off.sh
```
- **strict:** 853/443 rejected → DoT fails → **no answer** (refuses cleartext).
- **permissive:** fallback to cleartext → forged → **172.16.1.30 (lands)**.

### Tear down
```bash
sudo docker compose exec -T attacker pkill -x mitm || true
sudo docker compose exec -T edge-router /scripts/divert-off.sh
sudo docker compose down
```

---

## Results — six (attempt × client) combinations

| Attempt | Strict client (refuses cleartext) | Permissive client (allows fallback) |
|---|---|---|
| (i) alter in transit | **blocked** — TLS integrity aborts the session, no answer | **lands** — falls back, forged → rogue |
| (ii) rogue certificate | **blocked** — cert fails to validate, no answer | **lands** — falls back, forged → rogue |
| (iii) deny transport | **blocked** — no DoT, refuses cleartext, no answer | **lands** — falls back, forged → rogue |

## Report answers (7.4)

**For each attempt and client, worked or not, and why.** Against the **strict**
client no attempt lands: TLS gives the last mile confidentiality (the attacker
can't read the query to know what to forge) and integrity + authentication (it
can't alter the bytes, and a rogue cert fails to chain to the lab CA / match the
hostname). The worst the attacker achieves is **denial** — and the strict client
treats denial as failure rather than dropping to cleartext. Against the
**permissive** client every attempt lands, but not by breaking TLS: each attempt
merely *denies* DoT (corruption aborts it, the rogue cert is rejected, or the
port is blocked), and the client's own willingness to **fall back to cleartext**
hands the answer to the Phase-6 forger. The vulnerability is the fallback policy,
not the cryptography.

**DoT or DoH — which, and its drawbacks.** We deployed **DoT** (TCP 853) as the
client transport (DoH/443 is also enabled on the resolver). DoT's drawback versus
DoH: it uses a dedicated well-known port, so it is trivially identified and
**blocked** by a network operator (attempt iii) — exactly what forces the
fallback here. DoH hides DNS inside ordinary HTTPS on 443, which resists that
blocking and censorship, but at the cost of being harder for a site operator to
monitor or filter, more complex (full HTTP/2 stack), and often centralised in
browsers. Neither changes the integrity/authentication story; they differ mainly
in blockability and operational visibility.

**What an encrypted, authenticated last mile still does not protect.** It secures
only the stub↔resolver channel. It does **not**: make an unsigned or
downgraded zone trustworthy (that is DNSSEC's job, Phases 3–4); stop a resolver
that itself lies or is compromised; hide metadata such as *that* and *when* DNS
is happening, destination IPs, or TLS SNI/size side-channels; or protect a client
that accepts cleartext fallback or skips certificate validation. Confidentiality
and last-mile integrity are necessary but not sufficient — end-to-end trust still
needs DNSSEC validation (ideally on the client) plus a no-downgrade policy.

## Deliverables / evidence

| File | Shows |
|---|---|
| `evidence/p7-verify-strict.txt` | DoT resolution, cert valid, `172.16.1.20` |
| `evidence/p7-verify-no-cleartext.txt` | empty port-53 capture of the last mile |
| `evidence/p7-i-*.txt` | attempt (i) strict vs permissive |
| `evidence/p7-ii-*.txt` | attempt (ii) strict vs permissive |
| `evidence/p7-iii-*.txt` | attempt (iii) strict vs permissive |
| `evidence/mitm*.log`, `rogue-sserver.log` | attacker + rogue-responder activity |

## Notes / troubleshooting

- BIND DoH uses the built-in `http default` endpoint `/dns-query`. If `named`
  rejects `http default`, add `http default { endpoints { "/dns-query"; }; };`
  above `options` and reload.
- `iptables` in a container uses the nft backend; it needs the `NET_ADMIN`
  capability (the routers have it). If a rule is rejected, confirm with
  `sudo docker compose exec edge-router iptables -S`.
- If `kdig +tls` cannot resolve `resolver.cs6008.local`, confirm the client's
  `extra_hosts` entry: `sudo docker compose exec client getent hosts resolver.cs6008.local`.
