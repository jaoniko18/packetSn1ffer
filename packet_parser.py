import socket
import struct


class PacketParser:

    def __init__(self):
        pass
    @staticmethod
    def parse_ip_header(packet):

        if len(packet) < 20:
            raise ValueError("Invalid packet length")

        version = packet[0] >> 4 #moving away Ethernet header
        if version != 4:
            raise ValueError("Not IPv4")

        ihl = packet[0] & 0x0F
        header_length = ihl * 4

        if header_length < 20 or len(packet) < header_length:
            raise ValueError("Invalid packet length")

        src_ip = socket.inet_ntoa(packet[12:16])
        dst_ip = socket.inet_ntoa(packet[16:20])

        protocol_byte = packet[9]

        if protocol_byte == 6:
            protocol = "tcp"
        elif protocol_byte == 17:
            protocol = "udp"
        elif protocol_byte == 1:
            protocol = "icmp"
        else:
            protocol = "unknown"


        return src_ip, dst_ip, protocol, header_length

    @staticmethod
    def parse_transport_header(packet):
        src_ip, dst_ip, protocol, header_length = PacketParser.parse_ip_header(packet)

        src_port = ""
        dst_port = ""

        if protocol in ["tcp", "udp"]:
            src_port = int.from_bytes(packet[header_length:header_length + 2], "big")
            dst_port = int.from_bytes(packet[header_length + 2:header_length + 4], "big")

        return src_port, dst_port

