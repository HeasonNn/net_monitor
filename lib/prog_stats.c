#define _POSIX_C_SOURCE 200809L

#include "prog_stats.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <pthread.h>

FILE *log_file = NULL;
__u64 boot_time = 0;

__u64 get_boot_time() {
  FILE *btime_file = fopen("/proc/stat", "r");
  if (!btime_file) {
    perror("Error: Unable to open /proc/stat");
    return 0;
  }
  char line[256];
  __u64 boot_time = 0;
  while (fgets(line, sizeof(line), btime_file)) {
    if (sscanf(line, "btime %llu", &boot_time) == 1) {
      break;
    }
  }
  fclose(btime_file);
  return boot_time;
}

// 格式化 IP 地址
void format_ip(__u32 ip, char *buffer) {
  snprintf(buffer, 16, "%u.%u.%u.%u", ip & 0xFF, (ip >> 8) & 0xFF,
           (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

void init_log() {
  log_file = fopen("./flow_log.txt", "a+");
  if (!log_file) {
    perror("Error: Unable to open log file");
    exit(1);
  }
  boot_time = get_boot_time();
}

// 关闭日志文件
void close_log() {
  if (log_file) {
    fclose(log_file);
  }
}

// 打印 flow_log
static int handle_event(void *ctx, void *data, size_t data_sz) {
  struct flow_log *log = data;

  char src_ip[16], dst_ip[16];
  format_ip(log->src_ip, src_ip);
  format_ip(log->dst_ip, dst_ip);

  // 计算日志时间
  time_t log_time = boot_time + (log->timestamp / 1000000000);
  struct tm *tm_info = localtime(&log_time);
  char readable_time[64];
  strftime(readable_time, sizeof(readable_time), "%Y-%m-%d %H:%M:%S", tm_info);

  // 公共日志信息
  fprintf(log_file,
          "Packet Info:\n"
          "  Timestamp: %llu (%s)\n"
          "  Src IP: %s, Dst IP: %s\n"
          "  Src Port: %u, Dst Port: %u\n"
          "  Packet Length: %u bytes\n"
          "  Action: %u\n"
          "  Encrypted: %s\n",
          log->timestamp, readable_time, src_ip, dst_ip, log->src_port,
          log->dst_port, log->packet_len, log->action,
          log->is_encrypted ? "Yes" : "No");

  // 根据协议类型打印详细日志
  switch (log->protocol) {
    case 6:  // TCP
      fprintf(log_file,
              "  Protocol: TCP\n"
              "  TCP Flags: 0x%02x\n",
              log->proto_fields.tcp.tcp_flags);

      // 判断是否为 SSH 流量
      if (log->src_port == 22 || log->dst_port == 22) {
        fprintf(log_file,
                "  Application: SSH\n"
                "  SSH Version: %u\n",
                log->proto_fields.tcp.ssh_version);
      }
      break;

    case 17:  // UDP
      fprintf(log_file, "  Protocol: UDP\n");

      // 判断是否为 DNS 流量
      if (log->src_port == 53 || log->dst_port == 53) {
        fprintf(log_file,
                "  Application: DNS\n"
                "  DNS QR: %u, DNS RCODE: %u\n",
                log->proto_fields.dns.dns_qr, log->proto_fields.dns.dns_rcode);
      }
      break;

    case 1:  // ICMP
      fprintf(log_file,
              "  Protocol: ICMP\n"
              "  ICMP Type: %u, ICMP Code: %u\n",
              log->proto_fields.icmp.icmp_type,
              log->proto_fields.icmp.icmp_code);
      break;

    case 132:  // SCTP
      fprintf(log_file, "  Protocol: SCTP\n");
      break;

    case 50:  // ESP (加密)
      fprintf(log_file, "  Protocol: ESP (Encrypted)\n");
      break;

    case 51:  // AH (加密)
      fprintf(log_file, "  Protocol: AH (Authenticated)\n");
      break;

    default:
      fprintf(log_file, "  Protocol: Unknown (%u)\n", log->protocol);
      break;
  }

  // 打印分隔线
  fprintf(log_file, "----------------------------------------\n");
  fprintf(log_file, "\n");

  fflush(log_file);  // 及时刷新
  return 0;
}

// 读取环形缓冲区日志
static void read_flow_logs(int ringbuf_fd) {
  init_log();  // 初始化日志文件和启动时间
  struct ring_buffer *rb =
      ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
  if (!rb) {
    fprintf(stderr, "Error: Failed to create ring buffer\n");
    return;
  }

  while (1) {
    int err = ring_buffer__poll(rb, 1000);
    if (err < 0) {
      fprintf(stderr, "Error: ring_buffer__poll failed (%d)\n", err);
      break;
    }
  }

  ring_buffer__free(rb);
  close_log();  // 关闭日志文件
}

int ebpf_prog_stats(struct config *cfg) {
  int err;

  struct bpf_map_info info = {0};

  // 打开 flow_log_map
  int flow_log_map_fd = open_bpf_map_file(cfg->pin_dir, "flow_log_map", &info);
  CHECK_ERR(flow_log_map_fd < 0, "Error: Failed to get flow_log_map");

  // 创建线程读取 flow_log_map
  pthread_t flow_log_thread;
  pthread_create(&flow_log_thread, NULL, (void *(*)(void *))read_flow_logs,
                 (void *)(long)flow_log_map_fd);

  // 等待线程结束
  pthread_join(flow_log_thread, NULL);

  return 0;
}