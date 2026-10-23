# Full clean re-run — regenerate all evidence + screenshots in one pass

Run this top to bottom on your machine from `~/cs6008-dns-security`. Every phase
is torn down before the next so Docker never hits a network-pool overlap. Each
**SHOT** line tells you which terminal output (or tshark decode) to screenshot
and which report Figure it feeds.

> **Important about transaction IDs.** A fresh run produces brand-new random DNS
> transaction IDs and a new DNSSEC key tag. So after this run, the five code
> *listings* in the report that quote specific IDs will no longer match. The fix
> is simple: this run rewrites the evidence `.txt` files, and the screenshots
> come from the same run, so listings + screenshots + files all agree **once the
> five listing values are updated to the new run**. Commit the regenerated
> evidence at the end and I will align those five listings for you.

Screenshot a figure straight from the terminal output of the `tee` command that
produced it (the text is also saved in `phaseN/evidence/`).

---

## 0. One-time setup

```bash
cd ~/cs6008-dns-security
git pull origin main

# helper: full teardown of every phase + remove leftover lab networks
teardown() {
  for p in phase1 phase2 phase3 phase4 phase5 phase6 phase7; do
    (cd ~/cs6008-dns-security/$p && sudo docker compose down 2>/dev/null)
  done
  sudo docker network ls --format '{{.Name}}' | grep -E '^cs6008-p' | xargs -r sudo docker network rm 2>/dev/null
}
teardown

# build the shared image once (this also runs the BIND 9.20.x version check)
cd ~/cs6008-dns-security/phase1
sudo docker build -t cs6008-dns-lab:local -f ../common/Dockerfile ..
sudo docker run --rm cs6008-dns-lab:local named -v     # expect: BIND 9.20.x
```

---

## Phase 1 — hierarchy, resolution, isolation, referral capture

```bash
cd ~/cs6008-dns-security/phase1
mkdir -p evidence && chmod 777 evidence
sudo docker compose up -d --no-build
sudo docker compose ps -a

# --- resolution (Figure 2) ---
sudo docker compose exec -T client dig example.com A +time=3 +tries=1     | tee evidence/example-com.txt
sudo docker compose exec -T client dig www.example.com A +time=3 +tries=1 | tee evidence/www-example-com.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 10 http://example.com/ | tee evidence/legitimate-page.html
```
**SHOT (Figure 2):** the two `dig` outputs (both → 172.16.1.20) and the fetched page.

```bash
# --- isolation (Figure 3) ---
sudo docker compose exec -T client dig @172.16.3.10 example.com A +time=2 +tries=1 | tee evidence/direct-root-query.txt
```
**SHOT (Figure 3):** the failed direct-to-root query.

```bash
# --- referral capture (Figure 4) ---
sudo docker compose exec -d core-router sh -c '
  iface=$(ip -o -4 address show | awk '\''$4 == "172.16.2.3/24" { print $2 }'\'')
  test -n "$iface" || exit 1
  exec tcpdump -i "$iface" -nn -s 0 -U -Z root -w /evidence/core-dns.pcap "udp port 53 or tcp port 53" > /evidence/tcpdump.log 2>&1'
sleep 2
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig example.com A +time=3 +tries=1
sleep 2
sudo docker compose exec -T core-router pkill -INT -x tcpdump
sleep 2
# decode it as text and SCREENSHOT this (this is the Figure 4 placeholder you still need):
sudo docker compose exec -T core-router tshark -r /evidence/core-dns.pcap -Y dns | tee evidence/dns-packet-summary.txt
sudo docker compose exec -T core-router tshark -r /evidence/core-dns.pcap -Y dns -V > evidence/dns-packet-details.txt
```
**SHOT (Figure 4):** the `tshark ... -Y dns` summary showing the root → com → example.com referral chain.

```bash
sudo docker compose down
```

---

## Phase 2 — on-path response forgery

```bash
cd ~/cs6008-dns-security/phase2
mkdir -p evidence && chmod 777 evidence
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh

# --- transparent relay (Figure 5) ---
sudo docker compose exec -T core-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/interceptor > /evidence/relay.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig example.com A +time=3 +tries=1 | tee evidence/p2-relay-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 10 http://example.com/ | tee evidence/p2-relay-curl.txt
sudo docker compose exec -T attacker pkill -x interceptor || true
```
**SHOT (Figure 5):** relay dig → 172.16.1.20 and the real page.

```bash
# --- the attack (Figures 6 and 7) ---
IFACE=$(sudo docker compose exec -T core-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.2\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d core-router sh -c "exec tcpdump -i $IFACE -nn -s0 -c 300 -w /evidence/p2-attack.pcap 'udp port 53' > /evidence/p2-tcpdump.log 2>&1"
sleep 1
sudo docker compose exec -T core-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/interceptor --forge > /evidence/interceptor-forge.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush

sudo docker compose exec -T client dig example.com A +time=3 +tries=1          | tee evidence/p2-attack-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 10 http://example.com/ | tee evidence/p2-attack-curl.html
sudo docker compose exec -T client dig www.example.com A +time=3 +tries=1      | tee evidence/p2-nontarget-dig.txt

sudo docker compose exec -T attacker pkill -x interceptor || true
sudo docker compose exec -T core-router pkill -INT -x tcpdump || true
sudo docker compose exec -T core-router /scripts/divert-off.sh
sudo docker compose exec -T attacker cat /evidence/interceptor-forge.log | tee evidence/interceptor-forge.log
sudo docker compose exec -T core-router tshark -r /evidence/p2-attack.pcap -Y dns
```
**SHOT (Figure 6):** `p2-attack-dig.txt` (→172.16.1.30), the rogue page, and `p2-nontarget-dig.txt` (→172.16.1.20).
**SHOT (Figure 7):** the `tshark ... -Y dns` decode of `p2-attack.pcap` (this is the second Wireshark placeholder) and the `interceptor-forge.log` lines.

```bash
sudo docker compose down
sudo docker network ls --format '{{.Name}}' | grep -E '^cs6008-p' | xargs -r sudo docker network rm
```

---

## Phase 3 — DNSSEC chain of trust

```bash
cd ~/cs6008-dns-security/phase3
mkdir -p evidence && chmod 777 evidence
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh

# --- healthy validation (Figure 9) ---
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig +dnssec example.com A +time=3 +tries=1 | tee evidence/p3-valid-dig.txt
sudo docker compose exec -T client delv @172.16.2.10 -a /lab/configs/trust-anchors.conf example.com A 2>&1 | tee evidence/p3-valid-delv.txt
```
**SHOT (Figure 9):** `dig +dnssec` with the `ad` flag + RRSIG, and `delv` "fully validated".

```bash
# --- attack under DNSSEC (Figure 10) ---
sudo docker compose exec -T core-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/interceptor --forge > /evidence/interceptor-p3.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig example.com A +time=6 +tries=2 | tee evidence/p3-attack-dig-servfail.txt
sudo docker compose exec -T client sh -c "curl --noproxy '*' --fail --show-error --max-time 5 http://example.com/ ; echo curl-exit=\$?" | tee evidence/p3-attack-curl.txt
sudo docker compose exec -T attacker pkill -x interceptor || true
sudo docker compose exec -T core-router /scripts/divert-off.sh
```
**SHOT (Figure 10):** `p3-attack-dig-servfail.txt` (SERVFAIL) and the `curl` "Could not resolve host".

```bash
sudo docker compose down
sudo docker network ls --format '{{.Name}}' | grep -E '^cs6008-p' | xargs -r sudo docker network rm
```

---

## Phase 4 — signature stripping (Run A fails, Run B succeeds)

```bash
cd ~/cs6008-dns-security/phase4
mkdir -p evidence && chmod 777 evidence
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh

# --- verify through relay (Figure 11) ---
sudo docker compose exec -T core-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/stripper --relay > /evidence/stripper-relay.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig +dnssec example.com A +time=6 +tries=2 | tee evidence/a-verify-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --max-time 5 http://example.com/ | tee evidence/a-verify-curl.html
sudo docker compose exec -T attacker pkill -x stripper || true
```
**SHOT (Figure 11):** `ad` + 172.16.1.20 + real page through the relay.

```bash
# --- Run A attack: fails (Figure 12) ---
IFACE=$(sudo docker compose exec -T core-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.2\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d core-router sh -c "exec tcpdump -i $IFACE -nn -s0 -U -Z root -w /evidence/p4-runA.pcap 'udp port 53' > /evidence/p4-runA-tcpdump.log 2>&1"
sleep 1
sudo docker compose exec -T core-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/stripper --strip-runA > /evidence/stripper-runA.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig example.com A +time=6 +tries=2 | tee evidence/a-attack-dig.txt
sudo docker compose exec -T client sh -c "curl --noproxy '*' --fail --show-error --max-time 5 http://example.com/ ; echo curl-exit=\$?" | tee evidence/a-attack-curl.txt
sudo docker compose exec -T attacker pkill -x stripper || true
sudo docker compose exec -T core-router pkill -INT -x tcpdump || true
sudo docker compose exec -T core-router /scripts/divert-off.sh
sudo docker compose exec -T attacker cat /evidence/stripper-runA.log | tee evidence/stripper-runA.log
sudo docker compose logs resolver --since 2m | grep -Ei 'bogus|no valid|RRSIG|insecur|broken|DS ' | tee evidence/a-resolver-log.txt
```
**SHOT (Figure 12):** `stripper-runA.log` (STRIP/FORGE lines), `a-attack-dig.txt` (SERVFAIL), `a-resolver-log.txt` (broken trust chain).

```bash
# --- Run B: re-sign com WITHOUT the DS, attack succeeds (Figure 13) ---
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones-runB.sh
sudo docker compose restart tld-ns
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client delv @172.16.2.10 -a /lab/configs/trust-anchors.conf example.com A 2>&1 | tee evidence/b-delv-insecure.txt
sudo docker compose exec -T client dig example.com DS +dnssec | tee evidence/b-ds-nodata.txt

IFACE=$(sudo docker compose exec -T core-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.2\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d core-router sh -c "exec tcpdump -i $IFACE -nn -s0 -U -Z root -w /evidence/p4-runB.pcap 'udp port 53' > /evidence/p4-runB-tcpdump.log 2>&1"
sleep 1
sudo docker compose exec -T core-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/stripper --strip-runB > /evidence/stripper-runB.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig example.com A +time=6 +tries=2 | tee evidence/b-attack-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 5 http://example.com/ | tee evidence/b-attack-curl.html
sudo docker compose exec -T attacker pkill -x stripper || true
sudo docker compose exec -T core-router pkill -INT -x tcpdump || true
sudo docker compose exec -T core-router /scripts/divert-off.sh
```
**SHOT (Figure 13):** `b-delv-insecure.txt` ("unsigned answer"), `b-ds-nodata.txt`, `b-attack-dig.txt` (NOERROR, no `ad`, 172.16.1.30), rogue page.

```bash
sudo docker compose down
sudo docker network ls --format '{{.Name}}' | grep -E '^cs6008-p' | xargs -r sudo docker network rm
```

---

## Phase 5 — zone walking (NSEC leaks, NSEC3 closes it)

```bash
cd ~/cs6008-dns-security/phase5
mkdir -p evidence && chmod 777 evidence
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh

# --- NSEC signed denial (Figure 16) ---
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig +dnssec doesnotexist.example.com A +time=6 +tries=2 | tee evidence/p5-nxdomain.txt
```
**SHOT (Figure 16):** NXDOMAIN with the NSEC record + RRSIG.

```bash
# --- the walk (Figure 17) ---
sudo docker compose exec -T attacker /usr/local/bin/walker | tee evidence/p5-walk-nsec.txt
```
**SHOT (Figure 17):** the full walk recovering all 8 names.

```bash
# --- NSEC3 fix + re-walk (Figure 18) ---
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones-nsec3.sh
sudo docker compose restart domain-ns
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig +dnssec doesnotexist.example.com A +time=6 +tries=2 | tee evidence/p5-nxdomain-nsec3.txt
sudo docker compose exec -T attacker /usr/local/bin/walker | tee evidence/p5-walk-nsec3.txt
```
**SHOT (Figure 18):** NSEC3 hashed denial, and the re-run walk recovering 0 names.

```bash
sudo docker compose down
sudo docker network ls --format '{{.Name}}' | grep -E '^cs6008-p' | xargs -r sudo docker network rm
```

---

## Phase 6 — last-mile forgery (Client A fooled, Client B protected)

```bash
cd ~/cs6008-dns-security/phase6
mkdir -p evidence && chmod 777 evidence
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh

# --- verify relay (Figure 20) ---
sudo docker compose exec -T edge-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/forge --relay > /evidence/forge-relay.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client dig +dnssec example.com A +time=6 +tries=2 | tee evidence/p6-verify-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --max-time 5 http://example.com/ | tee evidence/p6-verify-curl.html
sudo docker compose exec -T attacker pkill -x forge || true
```
**SHOT (Figure 20):** `ad` + 172.16.1.20 + real page through the relay.

```bash
# --- the attack vs both clients (Figures 21 and 22) ---
IFACE=$(sudo docker compose exec -T edge-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.1\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d edge-router sh -c "exec tcpdump -i $IFACE -nn -s0 -U -Z root -w /evidence/p6-attack.pcap 'udp port 53' > /evidence/p6-tcpdump.log 2>&1"
sleep 1
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/forge --forge > /evidence/forge-attack.log 2>&1'
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush

sudo docker compose exec -T client dig example.com A +time=6 +tries=2 | tee evidence/p6-clientA-dig.txt
sudo docker compose exec -T client curl --noproxy '*' --fail --show-error --max-time 5 http://example.com/ | tee evidence/p6-clientA-curl.html
sudo docker compose exec -T client delv @172.16.2.10 -a /lab/configs/trust-anchors.conf example.com A 2>&1 | tee evidence/p6-clientB-delv.txt

sudo docker compose exec -T attacker pkill -x forge || true
sudo docker compose exec -T edge-router pkill -INT -x tcpdump || true
sudo docker compose exec -T edge-router /scripts/divert-off.sh
```
**SHOT (Figure 21):** Client A `dig` → 172.16.1.30 with `ad` set, and the rogue page.
**SHOT (Figure 22):** Client B `delv` → "insecurity proof failed" (captured with `2>&1`).

```bash
sudo docker compose down
sudo docker network ls --format '{{.Name}}' | grep -E '^cs6008-p' | xargs -r sudo docker network rm
```

---

## Phase 7 — encrypted last mile (DoT), 3 attacks x 2 clients

```bash
cd ~/cs6008-dns-security/phase7
mkdir -p evidence && chmod 777 evidence
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/make-pki.sh
sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash cs6008-dns-lab:local /lab/scripts/sign-zones.sh
sudo docker compose up -d
sudo docker compose exec -T attacker /scripts/build-attacker.sh
sudo docker compose ps -a      # confirm resolver is Up (not Exited)

# --- verified encrypted resolution (Figure 23) ---
IFACE=$(sudo docker compose exec -T edge-router sh -c 'ip -o -4 addr show' | grep -oE 'eth[0-9]+ +inet 172\.16\.1\.' | grep -oE 'eth[0-9]+' | head -1)
sudo docker compose exec -d edge-router sh -c "exec tcpdump -i $IFACE -nn -s0 -U -Z root -w /evidence/p7-verify.pcap 'host 172.16.1.10 and (port 53 or port 853 or port 443)' > /evidence/p7-verify-tcpdump.log 2>&1"
sleep 1
sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
sudo docker compose exec -T client /scripts/resolve-strict.sh | tee evidence/p7-verify-strict.txt
sudo docker compose exec -T edge-router pkill -INT -x tcpdump || true
sudo docker compose exec -T edge-router sh -c "tcpdump -nn -r /evidence/p7-verify.pcap 'port 53' | head" | tee evidence/p7-verify-no-cleartext.txt
```
**SHOT (Figure 23):** `p7-verify-strict.txt` (TLS1.3, cert valid, 172.16.1.20) and the empty port-53 read.

```bash
# --- put diversion + cleartext forger in place ---
sudo docker compose exec -T edge-router /scripts/divert-on.sh
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/mitm --forge-cleartext > /evidence/mitm.log 2>&1'

# attempt (i) alter in transit
sudo docker compose exec -T attacker pkill -x mitm || true
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/mitm --forge-cleartext --break-dot > /evidence/mitm-i.log 2>&1'
sudo docker compose exec -T client /scripts/resolve-strict.sh      | tee evidence/p7-i-strict.txt
sudo docker compose exec -T client /scripts/resolve-permissive.sh  | tee evidence/p7-i-permissive.txt
sudo docker compose exec -T attacker pkill -x mitm || true
sudo docker compose exec -d attacker sh -c 'exec /usr/local/bin/mitm --forge-cleartext > /evidence/mitm.log 2>&1'

# attempt (ii) rogue certificate
sudo docker compose exec -T edge-router /scripts/attack-rogue-on.sh
sudo docker compose exec -T client /scripts/resolve-strict.sh      | tee evidence/p7-ii-strict.txt
sudo docker compose exec -T client /scripts/resolve-permissive.sh  | tee evidence/p7-ii-permissive.txt
sudo docker compose exec -T edge-router /scripts/attack-rogue-off.sh

# attempt (iii) deny transport
sudo docker compose exec -T edge-router /scripts/attack-block-on.sh
sudo docker compose exec -T client /scripts/resolve-strict.sh      | tee evidence/p7-iii-strict.txt
sudo docker compose exec -T client /scripts/resolve-permissive.sh  | tee evidence/p7-iii-permissive.txt
sudo docker compose exec -T edge-router /scripts/attack-block-off.sh

sudo docker compose exec -T attacker pkill -x mitm || true
sudo docker compose exec -T edge-router /scripts/divert-off.sh
```
**SHOT (Figure 24):** the six files side by side — `p7-i/ii/iii-strict.txt` (each "refusing cleartext; NO answer") and `p7-i/ii/iii-permissive.txt` (each falling back to 172.16.1.30).

```bash
sudo docker compose down
sudo docker network ls --format '{{.Name}}' | grep -E '^cs6008-p' | xargs -r sudo docker network rm
```

---

## After the run

```bash
cd ~/cs6008-dns-security
git add phase*/evidence
git commit -m "Regenerate all evidence in one consistent run"
git push origin main
```

Then tell me it is pushed. The new run has new transaction IDs, so I will update
the five code listings in the report to match the fresh evidence files. After
that, drop your screenshots into the figures, rebuild, and upload `report.pdf` —
listings, screenshots, and evidence files will all come from this one run.
