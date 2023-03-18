#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define HTTP_FILTER_PORT 80

struct http_event_t {
    __u32 pid;
    __u32 direction;
};

BPF_PERF_OUTPUT(http_events);

int http_filter(struct xdp_md *ctx) {
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);

        if (tcp->dest == htons(HTTP_FILTER_PORT)) {
            // Incoming HTTP connection
            struct http_event_t event = {
                .pid = bpf_get_current_pid_tgid() >> 32,
                .direction = 0,
            };
            http_events.perf_submit(ctx, &event, sizeof(event));
        }

        if (tcp->source == htons(HTTP_FILTER_PORT)) {
            // Outgoing HTTP connection
            struct http_event_t event = {
                .pid = bpf_get_current_pid_tgid() >> 32,
                .direction = 1,
            };
            http_events.perf_submit(ctx, &event, sizeof(event));
        }
    }

    return XDP_PASS;
}
