#pragma once
#include <time.h>

#include "prog_helper.h"

#define NANOSEC_PER_SEC 1000000000  // 10^9

// 定义 flow_log 结构体，与 eBPF 程序中一致
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

int ebpf_prog_stats(struct config *cfg);