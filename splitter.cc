/*
 * Program to split pcaps into "sessions" based on
 * src-ip/dst-ip/src-port/dst-port. TCP and UDP "sessions" will be
 * split into the same files.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "SessionHash.h"

#include "fnv.h"

struct packet_stats {
    uint64_t count;
    uint64_t drop;
    uint64_t nonip;
    uint64_t ip6;
    uint64_t tcp;
    uint64_t udp;
    uint64_t other;
};

static void handle_packet(struct pcap_pkthdr *h, const u_char *pkt, struct packet_stats *s);

static void usage(const char *p)
{
    fprintf(stderr, "usage: %s -f <input.pcap>\n", p);
    exit(1);
}

int main(int argc, char **argv)
{
    char pcapError[PCAP_ERRBUF_SIZE];
    pcap_t *input;
    int link_type;
//    CSessionHash sessions;
    char *inputFile=NULL;
    int opt;

    int pcap_status;
    struct pcap_pkthdr *packet_header;
    const u_char *packet_data;

    struct packet_stats stats;

    while ((opt = getopt(argc, argv, "f:")) != -1) {
        switch(opt) {
        case 'f':
            inputFile = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }
    if (inputFile == NULL) {
        usage(argv[0]);
    }

    input = pcap_open_offline(inputFile, pcapError);
    if (input == NULL) {
        fprintf(stderr, "Couldn't open %s: %s\n", inputFile, pcapError);
        exit(1);
    }

    link_type = pcap_datalink(input);
    if (link_type != DLT_EN10MB) {
        fprintf(stderr, "unrecognized data-link type: %d\n", link_type);
        pcap_close(input);
        exit(1);
    }

    while ((pcap_status = pcap_next_ex(input, &packet_header, &packet_data)) == 1) {
        handle_packet(packet_header, packet_data, &stats);
    }

    if (pcap_status == -1) {
        fprintf(stderr, "Error reading file at packet %lu: %s\n", stats.count, pcap_geterr(input));
    } else {
        /* Normal end of input. */
        printf("Read %lu packets\n", stats.count);
    }

    pcap_close(input);
}

/*
 * Get the packets, calculate the session hash, and send them on their way.
 *
 * NOTE:
 *     no handling of 802.1q or other ethernet encapsulation.
 *     no handling of IP-in-IP
 *
 */
static void
handle_packet(struct pcap_pkthdr *h, const u_char *pkt, struct packet_stats *s)
{
    struct ether_header *eh;
    uint16_t type;

    struct iphdr *ip;

    uint8_t proto;
    uint8_t *src_addr;
    uint8_t *dst_addr;
    uint8_t addr_len;

    uint16_t src_port;
    uint16_t dst_port;

    uint8_t *p;

    if (h->caplen < (sizeof(struct ether_header) + sizeof(struct iphdr))) {
        s->drop++;
        return;
    }

    eh = (struct ether_header *)pkt;
    type = htons(eh->ether_type);
    if (type != ETHERTYPE_IP && type != ETHERTYPE_IPV6) {
        s->nonip++;
        return;
    }

    if (type == ETHERTYPE_IPV6) {
        s->ip6++;
        /* TODO: IP6, handling all possibly options isn't so easy. */
        return;
    }

    /* We've got an IPv4 packet. */
    ip = (struct iphdr *)(pkt + sizeof(struct ether_header));
    addr_len = 4; // IPv4 addresses are 4-bytes each.

    src_addr = (uint8_t *)&ip->saddr;
    dst_addr = (uint8_t *)&ip->daddr;

    p = (uint8_t *)ip;
    p += sizeof(struct iphdr);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;

        tcp = (struct tcphdr *)p;
        p += sizeof(struct tcphdr);

        if (p - pkt > h->caplen) {
            s->drop++;
            return;
        }
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;

        udp = (struct udphdr *)p;
        p += sizeof(struct udphdr);

        if (p - pkt > h->caplen) {
            s->drop++;
            return;
        }
        src_port = udp->source;
        dst_port = udp->dest;
    } else {
        s->other++;
        return;
    }

    /*
     * Make an arbitrary assumption of direction: servers have low ports.
     */
    if (src_port > dst_port) {

    } else {
    }
}
