import socket
from packet_parser import PacketParser
from dns_resolver import DNSResolver

class PacketSniffer:
    def __init__(self,interface:str):
        if interface not in ["eth0", "lo0", "en0"]:
            raise ValueError("Invalid interface")

        self.interface = interface
        self.socket = None


    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) #ipv4, raw socket, capture IP
        self.socket.bind((self.interface, 0)) #0 means no specific port(i want all packets)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #enabling promiscuous mode

        resolver = DNSResolver()

        while True:
            packet = self.capture_packet()
            src_ip, dst_ip, protocol = PacketParser.parse_ip_header(packet)
            src_port, dst_port = PacketParser.parse_transport_header(packet)

            src_name = resolver.resolve(src_ip)
            dst_name = resolver.resolve(dst_ip)
            print("Captured packet: ")
            print(f"{protocol} {src_name}:{src_port} -> {dst_ip}:{dst_name}")



    def capture_packet(self):
        packet, addr = self.socket.recvfrom(65535)
        return packet