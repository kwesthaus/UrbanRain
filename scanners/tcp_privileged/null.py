from scanners.tcp_privileged import xmas_null_fin

def run(targets, ports):
    # no flags should be set for null scan
    flags = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    xmas_null_fin.run(targets, ports, flags)
