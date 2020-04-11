from scanners.tcp_privileged import xmas_null_fin_maimon

def run(targets, ports, options, fragment_size, src_ip=None):
    # set FIN flag
    flags = [0, 0, 0, 0, 0, 0, 0, 0, 1]
    xmas_null_fin_maimon.run(targets, ports, flags, options, fragment_size, src_ip)
