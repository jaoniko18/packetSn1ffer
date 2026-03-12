"""
from scapy.all import conf
conf.use_pcap = True

from scapy.all import sniff
from packet_parser import PacketParser

parser = PacketParser()

def handle_packet(packet):
    raw_packet = bytes(packet)

    # remove ethernet header
    ip_packet = raw_packet[14:]

    try:
        src_ip, dst_ip, protocol, header_length = parser.parse_ip_header(ip_packet)
        src_port, dst_port = parser.parse_transport_header(ip_packet)

        print(protocol, src_ip, ":", src_port, "->", dst_ip, ":", dst_port)

    except:
        pass


print("Sniffer started...")

sniff(iface="en0", prn=handle_packet, store=False)
"""
from scapy.all import sniff

def handle(packet):
    if packet.haslayer("DNS"):
        print(packet.summary())

sniff(iface="en0", prn=handle, store=False)