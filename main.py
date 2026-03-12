from sniffer import PacketSniffer

def main():
    sniffer = PacketSniffer("en0")
    sniffer.start()

if __name__=="__main__":
    main()