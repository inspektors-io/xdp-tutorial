// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// XDP dump is simple program that dumps new IPv4 TCP connections through perf events.

#include "bpf_helpers.h"

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

// PerfEvent eBPF map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);


// PerfEvent item
struct perf_event_item {
  __u32 src_ip, dst_ip;
};
_Static_assert(sizeof(struct perf_event_item) == 8, "wrong size of perf_event_item");

// XDP program //
SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u64 packet_size = data_end - data;

  // L2
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return XDP_ABORTED;
  }

  // L3
  if (ether->h_proto != 0x08) {  // htons(ETH_P_IP) -> 0x08
    // Non IPv4
    return XDP_PASS;
  }
  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    return XDP_ABORTED;
  }

  // Emit perf event for every IP packet
  if (ip->protocol) {
    struct perf_event_item evt = {
      .src_ip = ip->saddr,
      .dst_ip = ip->daddr,
    };
    // flags for bpf_perf_event_output() actually contain 2 parts (each 32bit long):
    //
    // bits 0-31: either
    // - Just index in eBPF map
    // or
    // - "BPF_F_CURRENT_CPU" kernel will use current CPU_ID as eBPF map index
    //
    // bits 32-63: may be used to tell kernel to amend first N bytes
    // of original packet (ctx) to the end of the data.

    // So total perf event length will be sizeof(evt) + packet_size
    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &evt, sizeof(evt));
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
