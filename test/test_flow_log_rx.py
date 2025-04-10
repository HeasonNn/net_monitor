from scapy.all import *
import time

def print_flow_log(packet):
    print("\n--- Flow Log ---")
    print(f"Timestamp (ns): {int(time.time_ns())}")

    if IP in packet:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Packet Length: {len(packet)}")
    
    if TCP in packet:
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"Protocol: TCP")
        print(f"TCP Flags: {packet[TCP].flags}")

        # 检查是否为 SSH 包
        if packet[TCP].dport == 22 or packet[TCP].sport == 22:
            if Raw in packet:
                ssh_version = packet[Raw].load.decode(errors="ignore")
                if ssh_version.startswith("SSH-"):
                    print(f"SSH Version: {ssh_version.strip()}")

    elif UDP in packet:
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
        print(f"Protocol: UDP")

    elif ICMP in packet:
        print(f"Protocol: ICMP")
        print(f"ICMP Type: {packet[ICMP].type}")
        print(f"ICMP Code: {packet[ICMP].code}")

    elif SCTP in packet:
        print(f"Source Port: {packet[SCTP].sport}")
        print(f"Destination Port: {packet[SCTP].dport}")
        print(f"Protocol: SCTP")

def packet_callback(packet):
    print_flow_log(packet)

if __name__ == "__main__":
    print("Sniffing for incoming packets...")
    sniff(filter="ip", iface="veth0", prn=packet_callback)
