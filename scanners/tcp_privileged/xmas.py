import cust_packet.tcp_packet
from scanners.tcp_privileged import xmas_null_fin_maimon

def run(targets, ports, options):
    # set FIN, PSH, and URG flags
    flags = [0, 0, 0, 1, 0, 1, 0, 0, 1]
    xmas_null_fin_maimon.run(targets, ports, flags, options)
