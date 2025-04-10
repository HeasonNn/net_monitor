#include "ebpf_monitor.bpf.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} ip_blacklist SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key);
  __type(value, __u8);
} ip_cidr_blacklist SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u16);
  __type(value, __u8);
} blocked_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct five_tuple);
  __type(value, __u8);
} firewall_rules SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} flow_log_map SEC(".maps");

/* 辅助函数：提取 SSH 版本号 */
static __always_inline int parse_ssh_version(char *payload, void *data_end,
                                             __u8 *ssh_version) {
  if ((void *)(payload + 4) > data_end) return -1;
  if (payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' &&
      payload[3] == '-') {
    char version[11] = {0};
    int version_len = 0;
#pragma unroll
    for (int i = 0; i < 10; i++) {
      if ((void *)(payload + 4 + i) >= data_end) break;
      char ch = payload[4 + i];
      if (ch == ' ' || ch == '\n') break;
      version[version_len++] = ch;
    }
    if (version_len > 0) {
      *ssh_version = version[0] - '0';
    }
  }

  return 0;
}

/* 辅助函数：检测 TCP 加密特征 */
static __always_inline __u8 check_encrypted_tcp(struct tcphdr *tcp,
                                                void *data_end,
                                                __u8 *ssh_version) {
  __u16 src_port = bpf_ntohs(tcp->source);
  __u16 dst_port = bpf_ntohs(tcp->dest);
  __u8 encrypted = 0;

  // 基于端口判断（网络序比较）
  if (src_port == 22 || dst_port == 22) {
    /* SSH 协议：解析 SSH 版本 */
    char *payload = (char *)tcp + tcp->doff * 4;
    parse_ssh_version(payload, data_end, ssh_version);
    return 1;
  }
  if (src_port == 443 || dst_port == 443 || src_port == 8443 ||
      dst_port == 8443) {
    return 1;
  }

  // 基于 payload 特征判断
  char *payload = (char *)tcp + tcp->doff * 4;
  if ((void *)(payload + 5) <= data_end) {
    // 检查 TLS ClientHello 特征: 0x16 0x01 0x00 0x00 0x00
    if (payload[0] == 0x16 && payload[1] == 0x01 && payload[2] == 0x00 &&
        payload[3] == 0x00 && payload[4] == 0x00)
      return 1;

    // 检查 HTTP/2 特征 ("HTTP/2")
    if ((void *)(payload + 6) <= data_end && payload[0] == 'H' &&
        payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P' &&
        payload[4] == '/' && payload[5] == '2')
      return 1;
  }
  return encrypted;
}

/* 辅助函数：检测 UDP 加密特征 */
static __always_inline __u8 check_encrypted_udp(struct udphdr *udp,
                                                void *data_end) {
  __u16 src_port = bpf_ntohs(udp->source);
  __u16 dst_port = bpf_ntohs(udp->dest);
  __u8 encrypted = 0;

  if (src_port == 443 || dst_port == 443 || src_port == 8443 ||
      dst_port == 8443)
    return 1;

  char *payload = (char *)udp + sizeof(struct udphdr);
  if ((void *)(payload + 5) <= data_end) {
    // 检查 DTLS 握手特征
    if (payload[0] == 0x16 && payload[1] == 0x01 && payload[2] == 0x00 &&
        payload[3] == 0x00 && payload[4] == 0x00)
      return 1;

    // 检查 QUIC 握手 ("QUIC")
    if ((void *)(payload + 4) <= data_end && payload[0] == 'Q' &&
        payload[1] == 'U' && payload[2] == 'I' && payload[3] == 'C')
      return 1;

    // 检查 DNSCrypt 特征 ("DNSC")
    if ((void *)(payload + 4) <= data_end && payload[0] == 'D' &&
        payload[1] == 'N' && payload[2] == 'S' && payload[3] == 'C')
      return 1;

    // 检查 DoH 特征 ("HTTP/2")
    if ((void *)(payload + 6) <= data_end && payload[0] == 'H' &&
        payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P' &&
        payload[4] == '/' && payload[5] == '2')
      return 1;

    // 检查 DoT 特征 ("DOTS")
    if ((void *)(payload + 4) <= data_end && payload[0] == 'D' &&
        payload[1] == 'O' && payload[2] == 'T' && payload[3] == 'S')
      return 1;
  }
  return encrypted;
}

/* 记录流量日志，使用 union 填充协议特定字段，并设置 is_encrypted */
static __always_inline void record_flow_log(struct xdp_md *ctx, __u32 src_ip,
                                            __u32 dst_ip, __u16 src_port,
                                            __u16 dst_port, __u8 protocol,
                                            __u8 icmp_type, __u8 icmp_code,
                                            __u8 dns_qr, __u8 dns_rcode,
                                            __u8 ssh_version, __u32 action,
                                            __u8 tcp_flags, __u8 is_encrypted) {
  struct flow_log *log =
      bpf_ringbuf_reserve(&flow_log_map, sizeof(struct flow_log), 0);
  if (!log) return;

  log->timestamp = bpf_ktime_get_ns();
  log->src_ip = src_ip;
  log->dst_ip = dst_ip;
  log->packet_len =
      (__u32)((void *)(long)ctx->data_end - (void *)(long)ctx->data);
  log->action = action;
  log->src_port = src_port;
  log->dst_port = dst_port;
  log->protocol = protocol;

  /* 根据协议选择性填充 union 内的数据 */
  if (protocol == IPPROTO_ICMP) {
    log->proto_fields.icmp.icmp_type = icmp_type;
    log->proto_fields.icmp.icmp_code = icmp_code;
  } else if (protocol == IPPROTO_TCP) {
    log->proto_fields.tcp.tcp_flags = tcp_flags;
    log->proto_fields.tcp.ssh_version = ssh_version;
  } else if (protocol == IPPROTO_UDP) {
    log->proto_fields.dns.dns_qr = dns_qr;
    log->proto_fields.dns.dns_rcode = dns_rcode;
  } else {
    log->proto_fields.raw[0] = 0;
    log->proto_fields.raw[1] = 0;
  }

  log->is_encrypted = is_encrypted;

  bpf_ringbuf_submit(log, 0);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  __u32 filter_type = STATS_TYPE_PASSED;
  __u8 is_encrypted = 0;

  // 检查数据包长度
  struct ethhdr *eth = data;
  if (unlikely((void *)(eth + 1) > data_end))
    return STATS_TYPE_TO_XDP_ACTION(STATS_TYPE_DROPPED);

  // 仅处理 IPv4 和 IPv6 数据包
  if (unlikely(eth->h_proto != htons(ETH_P_IP) &&
               eth->h_proto != htons(ETH_P_IPV6)))
    return STATS_TYPE_TO_XDP_ACTION(STATS_TYPE_PASSED);

  // 处理 IPv4 数据包
  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (unlikely((void *)(ip + 1) > data_end))
      return STATS_TYPE_TO_XDP_ACTION(STATS_TYPE_DROPPED);

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP &&
        protocol != IPPROTO_ICMP)
      return STATS_TYPE_TO_XDP_ACTION(STATS_TYPE_PASSED);

    __u16 src_port = 0, dst_port = 0;
    __u8 tcp_flags = 0, icmp_type = 0, icmp_code = 0;
    __u8 dns_qr = 0, dns_rcode = 0, ssh_version = 0;

    // 处理 ICMP 数据包
    if (protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
      if (unlikely((void *)(icmp + 1) > data_end))
        return STATS_TYPE_TO_XDP_ACTION(STATS_TYPE_DROPPED);

      icmp_type = icmp->type;
      icmp_code = icmp->code;
    }
    // 处理 TCP 数据包
    else if (protocol == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
      if (unlikely((void *)(tcp + 1) > data_end))
        return STATS_TYPE_TO_XDP_ACTION(STATS_TYPE_DROPPED);

      src_port = bpf_htons(tcp->source);
      dst_port = bpf_htons(tcp->dest);
      tcp_flags = tcp->syn | (tcp->ack << 1) | (tcp->fin << 2) |
                  (tcp->rst << 3) | (tcp->psh << 4) | (tcp->urg << 5);
      is_encrypted = check_encrypted_tcp(tcp, data_end, &ssh_version);
    }
    // 处理 UDP 数据包
    else if (protocol == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)(ip + 1);
      if (unlikely((void *)(udp + 1) > data_end))
        return STATS_TYPE_TO_XDP_ACTION(STATS_TYPE_DROPPED);

      src_port = bpf_htons(udp->source);
      dst_port = bpf_htons(udp->dest);

      // 检查是否为 DNS 流量并提取 QR 和 RCODE
      if (dst_port == 53 || src_port == 53) {
        struct dns_hdr *dns = (struct dns_hdr *)(udp + 1);
        if ((void *)(dns + 1) <= data_end) {
          dns_qr = (dns->flags >> 15) & 0x1;  // 提取 QR 位
          dns_rcode = dns->flags & 0xF;       // 提取 RCODE
        }
      }
      is_encrypted = check_encrypted_udp(udp, data_end);
    }

    // 1. 精确 IP 拦截 (源IP)
    if (bpf_map_lookup_elem(&ip_blacklist, &src_ip)) {
      filter_type = STATS_TYPE_BLOCK;
    } else {
      // 2. CIDR 段匹配
      struct lpm_key cidr_key = {.prefixlen = 24, .ip = src_ip};
      if (bpf_map_lookup_elem(&ip_cidr_blacklist, &cidr_key)) {
        filter_type = STATS_TYPE_BLOCK;
      }
      // 3. 端口过滤（TCP/UDP）
      else if ((src_port && bpf_map_lookup_elem(&blocked_ports, &src_port)) ||
               (dst_port && bpf_map_lookup_elem(&blocked_ports, &dst_port))) {
        filter_type = STATS_TYPE_BLOCK;
      }
      // 4. 五元组匹配
      else {
        struct five_tuple key = {.src_ip = src_ip,
                                 .dst_ip = dst_ip,
                                 .src_port = src_port,
                                 .dst_port = dst_port,
                                 .protocol = protocol};
        if (bpf_map_lookup_elem(&firewall_rules, &key))
          filter_type = STATS_TYPE_BLOCK;
      }
    }

    /* 记录流量日志 */
    record_flow_log(ctx, src_ip, dst_ip, src_port, dst_port, protocol,
                    icmp_type, icmp_code, dns_qr, dns_rcode, ssh_version,
                    filter_type, tcp_flags, is_encrypted);
  } else {  // IPv6
  }

out:
  return STATS_TYPE_TO_XDP_ACTION(filter_type);
}

char _license[] SEC("license") = "GPL";