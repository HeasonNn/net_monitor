#pragma once

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define STATS_TYPE_TO_XDP_ACTION(type)       \
  ((type) == STATS_TYPE_ALLOWED   ? XDP_PASS \
   : (type) == STATS_TYPE_PASSED  ? XDP_PASS \
   : (type) == STATS_TYPE_DROPPED ? XDP_DROP \
                                  : XDP_ABORTED)

typedef enum stats_type {
  STATS_TYPE_ALLOWED = 0,  // Packet explicitly allowed by filter
  STATS_TYPE_BLOCK,        // Packet explicitly blocked by filter
  STATS_TYPE_PASSED,       // Packet passed through XDP without processing
  STATS_TYPE_DROPPED,      // Packet dropped due to errors
  STATS_TYPE_MAX
} stats_type_t;

struct lpm_key {
  __u32 prefixlen;
  __u32 ip;
};

struct five_tuple {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
};

struct flow_log {
  __u64 timestamp;  // 时间戳 (纳秒)

  __u32 src_ip;      // 源 IP 地址 (IPv4)
  __u32 dst_ip;      // 目的 IP 地址 (IPv4)
  __u32 packet_len;  // 包长度
  __u32 action;      // 防火墙操作

  __u16 src_port;  // 源端口号 (TCP/UDP/SCTP)
  __u16 dst_port;  // 目的端口号 (TCP/UDP/SCTP)

  __u8 protocol;  // 协议类型 (TCP=6, UDP=17, ICMP=1, SCTP=132, ESP=50, AH=51)

  // 协议特定字段使用 union 分组，统一占用 2 个字节
  union {
    struct {
      __u8 tcp_flags;    // TCP 标记位 (SYN, ACK, FIN, RST 等)
      __u8 ssh_version;  // SSH 版本号 (仅在 SSH 会话中有效)
    } tcp;
    struct {
      __u8 icmp_type;  // ICMP 类型
      __u8 icmp_code;  // ICMP 代码
    } icmp;
    struct {
      __u8 dns_qr;     // DNS 查询响应标志
      __u8 dns_rcode;  // DNS 响应代码
    } dns;
    __u8 raw[2];  // 通用备用字段
  } proto_fields;

  __u8 is_encrypted;  // 标识是否为加密数据包 (0: 否, 1: 是)
};

struct dns_hdr {
  __u16 id;
  __u16 flags;
  __u16 qdcount;
  __u16 ancount;
  __u16 nscount;
  __u16 arcount;
};