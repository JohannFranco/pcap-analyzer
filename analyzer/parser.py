from scapy.all import rdpcap, IP, TCP, UDP

def load_pcap(filepath):
    print(f"[*] Loading: {filepath}")
    packets = rdpcap(filepath)
    print(f"[*] Packets loaded: {len(packets)}")
    return packets

def extract_connections(packets):
    connections = []
    for packet in packets:
        if IP in packet:
            entry = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": None,
                "dst_port": None,
                "timestamp": float(packet.time)
            }
            if TCP in packet:
                entry["protocol"] = "TCP"
                entry["dst_port"] = packet[TCP].dport
            elif UDP in packet:
                entry["protocol"] = "UDP"
                entry["dst_port"] = packet[UDP].dport
            connections.append(entry)
    return connections