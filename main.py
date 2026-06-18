import sys
from analyzer.parser import load_pcap, extract_connections
from analyzer.detector import detect_port_scans, detect_suspicious_ports
from analyzer.reporter import generate_report

PCAP_FILE = sys.argv[1] if len(sys.argv) > 1 else "samples/telnet-cooked.pcap"

packets = load_pcap(PCAP_FILE)
connections = extract_connections(packets)

alerts = detect_port_scans(connections) + detect_suspicious_ports(connections)
generate_report(connections, alerts)