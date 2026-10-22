/*
 * CS6008 Assignment 2 — Phase 5: Zone Walking via NSEC
 * ----------------------------------------------------
 * A C/libpcap enumerator (per the tooling rule, attacks use libpcap:
 * pcap_inject to send, pcap to capture). It recovers the full contents of
 * example.com using DNS queries only — no AXFR, no wordlist.
 *
 * Method: in a zone signed with NSEC, authenticated denial of existence is
 * provided by NSEC records that chain the EXISTING owner names in canonical
 * order, each in cleartext naming its successor. So:
 *   1. ask the resolver for  example.com NSEC   (DO set) -> the apex NSEC names
 *      the first name in the zone;
 *   2. ask  <that name> NSEC                      -> it names the next; ...
 *   3. repeat until the NSEC next-name wraps back to the apex.
 * That is (number of owner names + 1) queries — within the (+2) budget.
 *
 * Queries are injected with libpcap from a source UDP port the kernel has no
 * socket for, so replies are read with libpcap too (a kernel socket would never
 * see them). Target is the validating resolver on the same subnet; its MAC is
 * discovered by ARP (nothing hard-coded).
 *
 * Against an NSEC3-signed zone (the Phase 5 fix) the apex has no NSEC record, so
 * step 1 finds no next-name and the walk recovers nothing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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

#define MAX_PKT 2048
#define APEX "example.com"
#define RESOLVER_IP "172.16.2.10"
#define T_NSEC 47
#define MAX_NAMES 256

static pcap_t *handle = NULL;
static char g_dev[64] = "eth0";
static uint8_t g_amac[6], g_rmac[6];
static uint32_t g_aip_n, g_rip_n;

/* ---- checksums ---- */
static uint16_t checksum(const void *buf, size_t len) {
    uint32_t sum = 0; const uint16_t *p = buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}
struct pseudo_hdr { uint32_t s, d; uint8_t z, p; uint16_t l; } __attribute__((packed));
static uint16_t udp_checksum(const struct iphdr *ip, const struct udphdr *u,
                             const uint8_t *pl, size_t pll) {
    struct pseudo_hdr ph = { ip->saddr, ip->daddr, 0, IPPROTO_UDP,
                             htons((uint16_t)(sizeof(struct udphdr) + pll)) };
    size_t tot = sizeof(ph) + sizeof(struct udphdr) + pll;
    uint8_t *b = calloc(1, tot + 1); if (!b) return 0;
    struct udphdr t = *u; t.check = 0;
    memcpy(b, &ph, sizeof(ph));
    memcpy(b + sizeof(ph), &t, sizeof(t));
    memcpy(b + sizeof(ph) + sizeof(t), pl, pll);
    uint16_t r = checksum(b, tot); free(b);
    return r ? r : 0xFFFF;
}

/* ---- DNS name read (handles compression) ---- */
static int read_name(const uint8_t *m, size_t ml, size_t off, char *out, size_t os) {
    size_t o = 0, i = off; int jumped = 0, after = -1, guard = 0;
    if (out && os) out[0] = '\0';
    while (i < ml) {
        if (++guard > 128) return -1;
        uint8_t l = m[i];
        if ((l & 0xC0) == 0xC0) {
            if (i + 1 >= ml) return -1;
            if (!jumped) after = (int)(i + 2);
            i = ((l & 0x3F) << 8) | m[i + 1]; jumped = 1; if (i >= ml) return -1; continue;
        }
        if (l == 0) { if (!jumped) after = (int)(i + 1); break; }
        if (l > 63 || i + 1 + l > ml) return -1;
        i++;
        for (uint8_t k = 0; k < l; k++) {
            if (out && o + 2 < os) {
                char c = (char)m[i + k];
                if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                out[o++] = c;
            }
        }
        if (out && o + 1 < os) out[o++] = '.';
        i += l;
    }
    if (out && os) { if (o && out[o - 1] == '.') o--; out[o] = '\0'; }
    return after;
}
static int skip_name(const uint8_t *m, size_t ml, size_t off) { return read_name(m, ml, off, NULL, 0); }

/* ---- encode a dotted name into DNS wire labels; returns bytes written ---- */
static int encode_name(const char *name, uint8_t *out) {
    size_t p = 0; const char *s = name;
    if (strcmp(name, ".") == 0 || name[0] == '\0') { out[0] = 0; return 1; }
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t len = dot ? (size_t)(dot - s) : strlen(s);
        if (len == 0 || len > 63) break;
        out[p++] = (uint8_t)len;
        memcpy(out + p, s, len); p += len;
        if (!dot) break;
        s = dot + 1;
    }
    out[p++] = 0;
    return (int)p;
}

/* ---- build a DNS query (RD, EDNS DO) for <qname>/NSEC ---- */
static int build_query(uint16_t id, const char *qname, uint8_t *dns) {
    dns[0] = id >> 8; dns[1] = id & 0xFF;
    dns[2] = 0x01; dns[3] = 0x00;           /* RD */
    dns[4] = 0; dns[5] = 1;                  /* QD=1 */
    dns[6] = 0; dns[7] = 0;                  /* AN */
    dns[8] = 0; dns[9] = 0;                  /* NS */
    dns[10] = 0; dns[11] = 1;                /* AR=1 (OPT) */
    int p = 12;
    p += encode_name(qname, dns + p);
    dns[p++] = 0; dns[p++] = T_NSEC;         /* QTYPE NSEC */
    dns[p++] = 0; dns[p++] = 1;              /* QCLASS IN */
    /* EDNS0 OPT with DO bit */
    dns[p++] = 0;                            /* root name */
    dns[p++] = 0; dns[p++] = 41;             /* TYPE OPT */
    dns[p++] = 0x10; dns[p++] = 0x00;        /* UDP size 4096 */
    dns[p++] = 0;                            /* ext-rcode */
    dns[p++] = 0;                            /* version */
    dns[p++] = 0x80; dns[p++] = 0x00;        /* flags: DO */
    dns[p++] = 0; dns[p++] = 0;              /* rdlen 0 */
    return p;
}

/* ---- send a query frame to the resolver ---- */
static void send_query(uint16_t id, uint16_t sport, const char *qname) {
    uint8_t dns[512];
    int dlen = build_query(id, qname, dns);
    uint8_t frame[MAX_PKT];
    size_t l2 = sizeof(struct ether_header), l3 = sizeof(struct iphdr), l4 = sizeof(struct udphdr);
    struct ether_header *eth = (struct ether_header *)frame;
    memcpy(eth->ether_dhost, g_rmac, 6);
    memcpy(eth->ether_shost, g_amac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    struct iphdr *ip = (struct iphdr *)(frame + l2);
    ip->ihl = 5; ip->version = 4; ip->tos = 0;
    ip->tot_len = htons((uint16_t)(l3 + l4 + dlen));
    ip->id = htons(id); ip->frag_off = 0; ip->ttl = 64; ip->protocol = IPPROTO_UDP;
    ip->saddr = g_aip_n; ip->daddr = g_rip_n; ip->check = 0;
    ip->check = checksum(ip, l3);
    struct udphdr *u = (struct udphdr *)(frame + l2 + l3);
    u->source = htons(sport); u->dest = htons(53);
    u->len = htons((uint16_t)(l4 + dlen)); u->check = 0;
    u->check = udp_checksum(ip, u, dns, dlen);
    memcpy(frame + l2 + l3 + l4, dns, dlen);
    pcap_sendpacket(handle, frame, l2 + l3 + l4 + dlen);
}

/* ---- parse a captured reply; if it carries an NSEC RR, copy its next-name.
 * Returns 1 if an NSEC next-name was found, 0 if not (e.g. NSEC3), -1 error. */
static int parse_nsec_next(const uint8_t *dns, size_t dlen, uint16_t want_id,
                           char *owner_out, char *next_out, size_t osz) {
    if (dlen < 12) return -1;
    uint16_t id = (dns[0] << 8) | dns[1];
    if (id != want_id) return -1;
    uint16_t qd = (dns[4] << 8) | dns[5];
    uint16_t an = (dns[6] << 8) | dns[7];
    uint16_t ns = (dns[8] << 8) | dns[9];
    size_t p = 12;
    for (uint16_t i = 0; i < qd; i++) { int e = skip_name(dns, dlen, p); if (e < 0) return -1; p = (size_t)e + 4; }
    uint32_t total = (uint32_t)an + ns;
    for (uint32_t i = 0; i < total; i++) {
        size_t owner_off = p;
        int e = skip_name(dns, dlen, p); if (e < 0) return -1;
        size_t q = (size_t)e;
        if (q + 10 > dlen) return -1;
        uint16_t type = (dns[q] << 8) | dns[q + 1];
        uint16_t rdlen = (dns[q + 8] << 8) | dns[q + 9];
        size_t rdata = q + 10;
        if (rdata + rdlen > dlen) return -1;
        if (type == T_NSEC) {
            if (owner_out) read_name(dns, dlen, owner_off, owner_out, osz);
            if (read_name(dns, dlen, rdata, next_out, osz) < 0) return -1;
            return 1;
        }
        p = rdata + rdlen;
    }
    return 0;                                   /* no NSEC in this reply */
}

/* ---- capture one matching reply (timeout seconds) ---- */
static int recv_reply(uint16_t want_id, char *owner_out, char *next_out, size_t osz) {
    time_t start = time(NULL);
    while (time(NULL) - start < 3) {
        struct pcap_pkthdr *h; const u_char *pkt;
        int rc = pcap_next_ex(handle, &h, &pkt);
        if (rc == 0) continue;
        if (rc < 0) return -1;
        size_t min = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + 12;
        if (h->caplen < min) continue;
        struct ether_header *eth = (struct ether_header *)pkt;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;
        struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ether_header));
        if (ip->protocol != IPPROTO_UDP || ip->saddr != g_rip_n) continue;
        struct udphdr *u = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
        if (ntohs(u->source) != 53) continue;
        const uint8_t *dns = (const uint8_t *)u + sizeof(struct udphdr);
        size_t ulen = ntohs(u->len);
        if (ulen < sizeof(struct udphdr) + 12) continue;
        size_t dlen = ulen - sizeof(struct udphdr);
        if (dns + dlen > pkt + h->caplen) continue;
        int r = parse_nsec_next(dns, dlen, want_id, owner_out, next_out, osz);
        if (r >= 0) return r;                    /* matched our id (NSEC found or not) */
    }
    return -1;                                   /* timeout */
}

/* ---- ARP-resolve the resolver's MAC ---- */
struct arp_pkt { struct ether_header eth; uint16_t ht, pt; uint8_t hl, pl; uint16_t op;
                 uint8_t sha[6], spa[4], tha[6], tpa[4]; } __attribute__((packed));
static int arp_resolve(void) {
    for (int a = 0; a < 20; a++) {
        struct arp_pkt q; memset(&q, 0, sizeof(q));
        memset(q.eth.ether_dhost, 0xFF, 6);
        memcpy(q.eth.ether_shost, g_amac, 6);
        q.eth.ether_type = htons(ETHERTYPE_ARP);
        q.ht = htons(ARPHRD_ETHER); q.pt = htons(ETHERTYPE_IP); q.hl = 6; q.pl = 4;
        q.op = htons(ARPOP_REQUEST);
        memcpy(q.sha, g_amac, 6); memcpy(q.spa, &g_aip_n, 4); memcpy(q.tpa, &g_rip_n, 4);
        pcap_sendpacket(handle, (const u_char *)&q, sizeof(q));
        time_t s = time(NULL);
        while (time(NULL) - s < 1) {
            struct pcap_pkthdr *h; const u_char *p;
            if (pcap_next_ex(handle, &h, &p) != 1) continue;
            if (h->caplen < sizeof(struct arp_pkt)) continue;
            const struct arp_pkt *r = (const struct arp_pkt *)p;
            if (ntohs(r->eth.ether_type) != ETHERTYPE_ARP) continue;
            if (ntohs(r->op) != ARPOP_REPLY) continue;
            if (memcmp(r->spa, &g_rip_n, 4) != 0) continue;
            memcpy(g_rmac, r->sha, 6); return 0;
        }
    }
    return -1;
}

static int load_local(void) {
    struct ifaddrs *ifap, *ifa; int ip = 0, mac = 0;
    if (getifaddrs(&ifap)) return -1;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, g_dev)) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            g_aip_n = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr; ip = 1;
        } else if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *ll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (ll->sll_halen == 6) { memcpy(g_amac, ll->sll_addr, 6); mac = 1; }
        }
    }
    freeifaddrs(ifap);
    return (ip && mac) ? 0 : -1;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-i") && i + 1 < argc) strncpy(g_dev, argv[++i], sizeof(g_dev) - 1);

    inet_pton(AF_INET, RESOLVER_IP, &g_rip_n);
    if (load_local()) { fprintf(stderr, "cannot read %s addr/mac\n", g_dev); return 1; }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(g_dev, MAX_PKT, 1, 50, errbuf);
    if (!handle) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }

    if (arp_resolve()) { fprintf(stderr, "ARP of %s failed\n", RESOLVER_IP); return 1; }
    printf("[walker] resolver %s at %02x:%02x:%02x:%02x:%02x:%02x\n", RESOLVER_IP,
           g_rmac[0], g_rmac[1], g_rmac[2], g_rmac[3], g_rmac[4], g_rmac[5]);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp and src host " RESOLVER_IP " and src port 53",
                     1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "bpf: %s\n", pcap_geterr(handle)); return 1;
    }
    pcap_setfilter(handle, &fp);

    srand((unsigned)time(NULL) ^ getpid());
    char seen[MAX_NAMES][256]; int nseen = 0;
    char cur[256]; strncpy(cur, APEX, sizeof(cur) - 1); cur[sizeof(cur)-1] = '\0';
    int queries = 0;

    printf("[walker] starting NSEC walk of %s via resolver\n\n", APEX);
    for (int step = 0; step < MAX_NAMES; step++) {
        uint16_t id = (uint16_t)(rand() & 0xFFFF);
        uint16_t sport = (uint16_t)(40000 + (rand() % 20000));
        /* a couple of retries for lossy first packets */
        char owner[256] = {0}, next[256] = {0};
        int r = -1;
        for (int try = 0; try < 3 && r < 0; try++) {
            send_query(id, sport, cur);
            r = recv_reply(id, owner, next, sizeof(next));
        }
        queries++;
        if (r < 0) { printf("[walker] no reply for %s (timeout)\n", cur); break; }
        if (r == 0) {
            printf("[walker] %s: signed denial carries NO NSEC next-name "
                   "(NSEC3 or no DNSSEC) -> walk cannot continue\n", cur);
            break;
        }
        printf("  found: %-20s  next -> %s\n", owner[0] ? owner : cur, next);
        /* record owner */
        if (nseen < MAX_NAMES) { snprintf(seen[nseen], sizeof(seen[nseen]), "%s", owner[0] ? owner : cur); nseen++; }
        /* wrapped back to apex => done */
        if (strcasecmp(next, APEX) == 0) { printf("\n[walker] chain wrapped to apex — zone complete.\n"); break; }
        /* loop guard: already seen next */
        int dup = 0; for (int k = 0; k < nseen; k++) if (!strcasecmp(seen[k], next)) dup = 1;
        if (dup) { printf("\n[walker] next-name already seen — stopping.\n"); break; }
        strncpy(cur, next, sizeof(cur) - 1); cur[sizeof(cur)-1] = '\0';
    }

    printf("\n[walker] recovered %d owner name(s) in %d queries:\n", nseen, queries);
    for (int k = 0; k < nseen; k++) printf("    %s\n", seen[k]);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
