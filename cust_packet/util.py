# Nick Morris
import ipaddress

# convert IPv4Address object into binary representation
def parseIP(ip):
    return ipaddress.IPv4Address(ip).packed

# convert bytes object to an int using a big-endian interpretation
def btoi(bytes_obj):
    return int.from_bytes(bytes_obj, "big")
