import socket
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Protocol


IPAddress = IPv4Address | IPv6Address


class DNSResolver(Protocol):
    def resolve(self, hostname: str) -> tuple[IPAddress, ...]: ...


class SystemDNSResolver:
    def resolve(self, hostname: str) -> tuple[IPAddress, ...]:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = {
            ip_address(record[4][0].split("%", 1)[0])
            for record in records
        }
        return tuple(sorted(addresses, key=lambda item: (item.version, int(item))))

