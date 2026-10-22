# Phase 5 — Zone Walking (NSEC enumeration)

A signed zone must prove that a name does **not** exist, and that proof is signed
*ahead of time*. With **NSEC**, the proof is built by chaining the zone's
existing owner names in canonical order, each record naming its successor in
cleartext. So a denial for one name leaks the next real name — and by walking the
chain an attacker reconstructs the whole zone with DNS queries only (no AXFR, no
wordlist). The fix is **NSEC3**, which chains *hashes* of the names instead.

Reuses the Phase 3 signed, validating deployment. `example.com` is populated with
five unadvertised internal hosts — `backup, dev, git, mail, vpn` — plus the
public `www`/`ns`. The attacker sits on the resolver subnet (172.16.2.100) and
runs a **C/libpcap** walker (`src/walker.c`) that injects NSEC queries and reads
the replies off the wire.

```
phase5/
  compose.yml                 topology (= Phase 3, project cs6008-p5)
  configs/                    validating resolver + authoritative BIND configs
  zones/db.example.com        apex + www/ns + 5 hidden names (backup,dev,git,mail,vpn)
  scripts/
    sign-zones.sh             NSEC signing (walkable) — the leak
    sign-zones-nsec3.sh       the fix: re-sign example.com with NSEC3
    build-attacker.sh         compile src/walker.c -> /usr/local/bin/walker
  src/walker.c, Makefile      C/libpcap NSEC zone-walker
  evidence/                   generated
```

---

## 0. Prerequisites

```bash
sudo docker build -t cs6008-dns-lab:local -f ../common/Dockerfile ..   # once
mkdir -p evidence && chmod 777 evidence
```

## 1. Sign (NSEC — walkable) and deploy

```bash
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash \
     cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh
```

## 2. Verify 5.2 — how the zone denies a nonexistent name

```bash
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig +dnssec doesnotexist.example.com A +time=6 +tries=2 | tee evidence/p5-nxdomain.txt
```
Expect `status: NXDOMAIN` with an **NSEC** record (and its RRSIG) in the AUTHORITY
section whose owner/next span the queried name — a *signed* denial that also
discloses a real neighbouring name.

## 3. Attack 5.3a — walk the zone

```bash
sudo docker compose exec -T attacker /usr/local/bin/walker | tee evidence/p5-walk-nsec.txt
```
Expect the walker to follow the NSEC chain from the apex and print every owner,
ending with "chain wrapped to apex — zone complete", e.g.:

```
  found: example.com          next -> backup.example.com
  found: backup.example.com   next -> dev.example.com
  found: dev.example.com      next -> git.example.com
  found: git.example.com      next -> mail.example.com
  found: mail.example.com     next -> ns.example.com
  found: ns.example.com       next -> vpn.example.com
  found: vpn.example.com      next -> www.example.com
  found: www.example.com      next -> example.com
recovered 8 owner name(s) in 8 queries
```
Seven non-apex names recovered in 8 = (names + 1) queries — within the (+2) budget.
All five hidden hosts (`backup, dev, git, mail, vpn`) are exposed.

## 4. Attack 5.3b — close the leak with NSEC3, re-run the walk

```bash
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash \
     cs6008-dns-lab:local /lab/scripts/sign-zones-nsec3.sh
sudo docker compose restart domain-ns
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
```

Show a nonexistent name still gets an authenticated denial, now via NSEC3:
```bash
sudo docker compose exec -T client dig +dnssec doesnotexist.example.com A +time=6 +tries=2 | tee evidence/p5-nxdomain-nsec3.txt
```
Expect `NXDOMAIN` with **NSEC3** records (hashed owner names) + RRSIG — still a
valid signed denial, but no cleartext neighbour.

Re-run the walk — it now recovers nothing:
```bash
sudo docker compose exec -T attacker /usr/local/bin/walker | tee evidence/p5-walk-nsec3.txt
```
Expect: the apex query returns no NSEC next-name, so the walker reports
"signed denial carries NO NSEC next-name (NSEC3 ...) -> walk cannot continue" and
recovers 0 names.

## Tear down
```bash
sudo docker compose down
```

---

## Report answers (5.4)

**Names recovered, and the exact steps/queries.** `backup, dev, git, mail, vpn`
(the hidden hosts) plus `www`, `ns`, and the apex. The walker asks the resolver
`example.com NSEC` with the DO bit set; the apex NSEC names the first zone member
(`backup`); it then asks `backup.example.com NSEC`, whose record names `dev`, and
so on, until a record's next-name wraps back to the apex. That is one query per
owner name — 8 queries for 7 names.

**Which configuration made it possible, and why signed denial leaks when plain
DNS does not.** NSEC. Because authenticated denial must be *pre-signed* (the
server cannot mint a fresh signature per query without its online private key),
the proof cannot be about the queried name itself — it must point at names that
*do* exist, in canonical order. NSEC publishes those successor names in
cleartext, so each denial is a signed statement "between real name X and real
name Y nothing exists", handing the attacker Y. Plain (unsigned) DNS simply
returns NXDOMAIN with no such span, so it reveals nothing about other names.

**What the fix costs and what an enumerator can still learn.** NSEC3 hashes the
owner names (salted SHA-1) before chaining them, so a denial reveals only a hash,
not a neighbour. Costs: extra CPU to hash and larger denials; the salt/iteration
parameters must be chosen (low iterations are now recommended); and opt-out, if
enabled, weakens guarantees. What still leaks: the **number** of names (chain
length) and the hashes themselves, which an attacker can attack **offline** with
a dictionary/brute force (GPU hash-cracking) — NSEC3 raises the cost of
enumeration, it does not make it impossible. (NSEC5 / online-signing or
minimally-covering NSEC would remove even that, at the price of online keys.)

## Deliverables / evidence

| File | Shows |
|---|---|
| `evidence/p5-nxdomain.txt` | NSEC signed denial (leaks a neighbour) |
| `evidence/p5-walk-nsec.txt` | full walk recovering all names |
| `evidence/p5-nxdomain-nsec3.txt` | NSEC3 signed denial (hashed, no neighbour) |
| `evidence/p5-walk-nsec3.txt` | walk fails after the fix |
