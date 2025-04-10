from scapy.all import *
import time

"""
测试流量发送脚本
"""
def send_icmp(dst_ip):
    icmp_packet = IP(dst=dst_ip) / ICMP(type=8, code=0) / Raw(load="Test ICMP")
    send(icmp_packet)
    print(f"Sent ICMP packet to {dst_ip}")

def send_tcp(dst_ip, dst_port):
    tcp_packet = IP(dst=dst_ip) / TCP(sport=12345, dport=dst_port, flags="S") / Raw(load="Test TCP")
    send(tcp_packet)
    print(f"Sent TCP packet to {dst_ip}:{dst_port}")

def send_udp(dst_ip, dst_port):
    udp_packet = IP(dst=dst_ip) / UDP(sport=12345, dport=dst_port) / Raw(load="Test UDP")
    send(udp_packet)
    print(f"Sent UDP packet to {dst_ip}:{dst_port}")

def send_dns(dst_ip, dst_port, domain):
    dns_packet = IP(dst=dst_ip) / UDP(sport=12345, dport=dst_port) / DNS(rd=1, qd=DNSQR(qname=domain))
    send(dns_packet)
    print(f"Sent DNS packet to {dst_ip}:{dst_port} for domain {domain}")


"""
加密流量
"""

"""
TCP加密: 发送 SSH、TLS、HTTP/2 流量
"""
def send_ssh(dst_ip):
    pkt = IP(dst=dst_ip) / TCP(sport=12345, dport=22, flags="S") / Raw(load="SSH-2.0-OpenSSH_9.4\r\n")
    send(pkt)
    print(f"Sent SSH banner packet to {dst_ip}:22")

def send_tls_client_hello(dst_ip):
    tls_payload = bytes([0x16, 0x01, 0x00, 0x00, 0x00]) + b'\x00' * 10
    pkt = IP(dst=dst_ip) / TCP(sport=12345, dport=443, flags="S") / Raw(load=tls_payload)
    send(pkt)
    print(f"Sent TLS ClientHello to {dst_ip}:443")

def send_http2_tcp(dst_ip):
    pkt = IP(dst=dst_ip) / TCP(sport=12345, dport=8443, flags="S") / Raw(load=b"HTTP/2")
    send(pkt)
    print(f"Sent HTTP/2 packet to {dst_ip}:8443 over TCP")


"""
UDP加密: 发送 DTLS、QUIC、DNSCrypt、DoH、DoT 流量
"""
def send_dtls_udp(dst_ip):
    dtls_payload = bytes([0x16, 0x01, 0x00, 0x00, 0x00]) + b'\x00' * 10
    pkt = IP(dst=dst_ip) / UDP(sport=12345, dport=443) / Raw(load=dtls_payload)
    send(pkt)
    print(f"Sent DTLS packet to {dst_ip}:443 over UDP")

def send_quic_udp(dst_ip):
    pkt = IP(dst=dst_ip) / UDP(sport=12345, dport=443) / Raw(load=b"QUIC" + b"\x00" * 10)
    send(pkt)
    print(f"Sent QUIC packet to {dst_ip}:443 over UDP")

def send_dnscrypt_udp(dst_ip):
    pkt = IP(dst=dst_ip) / UDP(sport=12345, dport=443) / Raw(load=b"DNSC" + b"\x00" * 10)
    send(pkt)
    print(f"Sent DNSCrypt packet to {dst_ip}:443 over UDP")

def send_doh_udp(dst_ip):
    pkt = IP(dst=dst_ip) / UDP(sport=12345, dport=443) / Raw(load=b"HTTP/2" + b"\x00" * 10)
    send(pkt)
    print(f"Sent DoH packet to {dst_ip}:443 over UDP")

def send_dot_udp(dst_ip):
    pkt = IP(dst=dst_ip) / UDP(sport=12345, dport=443) / Raw(load=b"DOTS" + b"\x00" * 10)
    send(pkt)
    print(f"Sent DoT packet to {dst_ip}:443 over UDP")

if __name__ == "__main__":
    dst_ip = "192.168.10.1"  # 接收端 IP

    # 基础流量
    send_icmp(dst_ip)
    send_tcp(dst_ip, 8080)
    send_udp(dst_ip, 8081)
    send_dns(dst_ip, 53, "example.com")  # 发送 DNS 查询包

    # TCP 加密流量
    send_ssh(dst_ip, 22)  # 发送 SSH 包
    send_tls_client_hello(dst_ip)
    send_http2_tcp(dst_ip)

    # UDP 加密流量
    send_dtls_udp(dst_ip)
    send_quic_udp(dst_ip)
    send_dnscrypt_udp(dst_ip)
    send_doh_udp(dst_ip)
    send_dot_udp(dst_ip)
