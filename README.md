PCAP Analyzer

A Python-based network traffic analyzer that parses PCAP files and detects suspicious patterns. 


Features

- Parses PCAP files using Scapy
- Detects port scanning activity
- Flags connections to suspicious ports (Telnet, common C2 ports)
- Generates timestamped JSON reports per run
- Fully Dockerized runs with a single command


Requirements

Python 3.11+, Docker
