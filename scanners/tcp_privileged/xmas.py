import cust_packet.tcp_packet
from scanners.tcp_privileged import xmas_null_fin

def run(targets, ports):
    # set FIN, PSH, and URG flags
    flags = [0, 0, 0, 1, 0, 1, 0, 0, 1]
    xmas_null_fin.run(targets, ports, flags)
