# Mark Gilliland and David Levine
from scanners.tcp_privileged import xmas_null_fin_maimon

def run(targets, ports, options, fragment_size, src_ip=None, print_results=True):
    # no flags should be set for null scan
    flags = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    xmas_null_fin_maimon.run(targets, ports, flags, options, fragment_size, src_ip, print_results)
