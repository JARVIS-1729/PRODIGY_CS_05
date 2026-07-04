import argparse
from scapy.all import sniff, UDP , TCP, ICMP ,IP, Raw

def inspector(packet):

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst


        protocol = "OTHER"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        payload_data = ""

        if packet.haslayer(Raw):
            raw_bytes = packet[Raw].load

            decoded_text = raw_bytes.decode('utf-8', 'ignore')[:50]
            clean_text = decoded_text.replace("\n", " ").replace("\r", " ")
            payload_data = f" | Payload: {clean_text}"


        print(f"Source IP: {ip_src:<15} | Destination IP: {ip_dst:<15} | Protocol: {protocol}{payload_data}")

def sniffer(interface):
    print(f" Listening on interface: {interface}")
    print("Waiting for network data... (press ctrl+c to terminate)")
    print('-'*70)
    
    
    sniff(iface=interface, prn=inspector,store=False )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument('-i', '--interface', default="eth0", help="The network interface to listen on (eth0 is default)")
    
    args = parser.parse_args()

    try:
        sniffer(args.interface)
    except PermissionError:
        print(" Root privileges required. Please run with 'sudo'.")
    except KeyboardInterrupt:
        print("\n Stopping the sniffer... Keyboard interrupted.")