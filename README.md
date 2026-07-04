# PRODIGY_CS_05

Task 05: Network Packet Analyzer (Packet Sniffer)

A robust network forensics tool built for Kali Linux. By setting the network interface to promiscuous mode, this script intercepts and analyzes live packet traffic flying across the network.

Concept: Network Layers, Promiscuous Mode, Packet Forging, and Berkeley Packet Filters (BPF).

Features:

Extracts Source IP, Destination IP, Protocol, and Raw Payload Data.

Utilizes BPF (tcp port 80) to filter out UDP background noise and heavily encrypted HTTPS gibberish.

Successfully intercepts plaintext HTTP web requests, server headers, and User-Agent fingerprints.

Tech Stack: Python, scapy, Kali Linux (Bridged VM Network)
