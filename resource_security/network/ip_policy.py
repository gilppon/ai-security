from ipaddress import IPv4Address, IPv6Address


IPAddress = IPv4Address | IPv6Address
METADATA_IPS = {IPv4Address("169.254.169.254")}


def blocked_ip_reason(address: IPAddress) -> str | None:
    if address in METADATA_IPS:
        return "METADATA_ENDPOINT"
    if not address.is_global:
        return "PRIVATE_NETWORK_DESTINATION"
    return None

