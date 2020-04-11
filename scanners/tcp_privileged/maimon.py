from scanners.tcp_privileged import xmas_null_fin_maimon

def run(targets, port_range, options, fragment_size, src_ip=None):
    # set FIN and ACK flags
    flags = [0, 0, 0, 0, 1, 0, 0, 0, 1]
    xmas_null_fin_maimon.run(targets, port_range, flags, options, fragment_size, src_ip)
