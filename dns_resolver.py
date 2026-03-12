import socket
class DNSResolver:
    def __init__(self):
        self.cache = {}

    def resolve(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            name = socket.gethostbyaddr(ip)[0]
        except:
            name = ip

        self.cache[ip] = name
        return name
