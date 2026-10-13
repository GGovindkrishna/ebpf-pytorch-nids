#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

struct data_t {
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned char protocol;
    unsigned int pkt_len;
};

BPF_RINGBUF_OUTPUT(events, 16);

int monitor_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __builtin_bswap16(0x0800)) // ETH_P_IP
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct data_t *item = events.ringbuf_reserve(sizeof(struct data_t));
    if (!item)
        return XDP_PASS;

    item->saddr = ip->saddr;
    item->daddr = ip->daddr;
    item->protocol = ip->protocol;
    item->pkt_len = (unsigned int)(data_end - data);
    item->sport = 0;
    item->dport = 0;

    if (ip->protocol == 6) { // IPPROTO_TCP
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            item->sport = __builtin_bswap16(tcp->source);
            item->dport = __builtin_bswap16(tcp->dest);
        }
    } else if (ip->protocol == 17) { // IPPROTO_UDP
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            item->sport = __builtin_bswap16(udp->source);
            item->dport = __builtin_bswap16(udp->dest);
        }
    }

    events.ringbuf_submit(item, 0);
    return XDP_PASS;
}
