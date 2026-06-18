from collections import defaultdict

SUSPICIOUS_PORTS = {23, 1337, 8080, 31337, 9001, 6667}
PORT_SCAN_THRESHOLD = 15

def detect_port_scans(connections):
    src_to_ports = defaultdict(set)
    for conn in connections:
        if conn["dst_port"]:
            src_to_ports[conn["src_ip"]].add(conn["dst_port"])

    alerts = []
    for src_ip, ports in src_to_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN",
                "src_ip": src_ip,
                "ports_scanned": len(ports),
                "severity": "HIGH"
            })
    return alerts

def detect_suspicious_ports(connections):
    alerts = []
    seen = {}  
    
    for conn in connections:
        if conn["dst_port"] in SUSPICIOUS_PORTS:
            pair = (conn["src_ip"], conn["dst_ip"], conn["dst_port"])
            if pair not in seen:
                seen[pair] = 0
            seen[pair] += 1

    for (src, dst, port), count in seen.items():
        alerts.append({
            "type": "SUSPICIOUS_PORT",
            "src_ip": src,
            "dst_ip": dst,
            "port": port,
            "packet_count": count,
            "severity": "MEDIUM"
        })
    return alerts