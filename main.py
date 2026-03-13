from scapy.all import conf
conf.use_pcap = True

from scapy.all import sniff
from packet_parser import PacketParser
from scapy.layers.dns import DNS, DNSRR

dns_cache = {}
traffic_stats = {}
packet_counter = 0
parser = PacketParser()

def handle_packet(packet):
    global packet_counter
    packet_counter += 1
    if packet.haslayer(DNS): #does packet has a dns layer?
        dns = packet[DNS]
        if dns.qr == 1: # response = 1, 0 = query
            #extract name
            for i in range(dns.ancount):
                answer = dns.an[i]

                if isinstance(answer, DNSRR):
                    domain = answer.rrname.decode().rstrip('.')
                    ip = answer.rdata #extract ip

                    if isinstance(ip, str):
                        dns_cache[ip] = domain #add to database(cache)
                        print(f"DNS cached: {domain} -> {ip} ")
                    elif isinstance(ip, list):
                        for j in range(len(ip)):
                            dns_cache[ip[j]] = domain
                            print(f"DNS cached: {domain} -> {ip[j]} ")

    raw_packet = bytes(packet)

    # remove ethernet header
    ip_packet = raw_packet[14:]

    try:
        src_ip, dst_ip, protocol, header_length = parser.parse_ip_header(ip_packet)
        src_port, dst_port = parser.parse_transport_header(ip_packet)


        if src_port==80 or dst_port==80:
            print("HTTP is detected")

        if dst_ip in dns_cache:
            domain_dst = dns_cache[dst_ip]
        else:
            domain_dst = dst_ip
        if src_ip in dns_cache:
            domain_src = dns_cache[src_ip]
        else:
            domain_src = src_ip
        if domain_dst in traffic_stats:
            traffic_stats[domain_dst] += 1
        else:
            traffic_stats[domain_dst] = 1


        if packet_counter % 100 == 0:
            print(f"Packet counter: {packet_counter}")
            print(f"-----Traffic statistics-----------")
            for k, v in traffic_stats.items():
                print(f"{k}: {v}")
            print(f"-----End of statistics-----------")
        print(protocol, domain_src, ":", src_port, "->", domain_dst, ":", dst_port)

    except:
        pass


print("Sniffer started...")

sniff(iface="en0", prn=handle_packet, store=False)
