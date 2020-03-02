import argparse
import ipaddress
from scanners import host_up, tcp_connect, udp_connect, ping_os
from scanners.util.host_parser import parse_hosts
import socket
import re

# Parser for port ranges
def parseNumRange(string):
    m = re.match(r'(\d+)(?:-(\d+))?$', string)
    if not m:
        raise ArgumentTypeError("'" + string + "' is not a range of numbers (e.g. '80-100').")
    start = m.group(1)
    end = m.group(2) or start
    return list(range(int(start,10), int(end,10)+1))

def main():

    # Parse args
    parser = argparse.ArgumentParser(description='A simple python network scanner.')
    parser.add_argument('discovery', choices=['host', 'port', 'both'], help='which type of discovery should occur')
    parser.add_argument('targets',  nargs='+', help='CIDR range of targets to scan')
    parser.add_argument('-p', '--port-range', type=parseNumRange, help='range of ports to scan')
    parser.add_argument('-sT', action='store_true', help='run an unprivileged TCP Connect scan')
    parser.add_argument('-sU', action='store_true', help='run an unprivileged UDP Connect scan')
    parser.add_argument('-sP', action='store_true', help='run an unprivileged PING scan')
    parser.add_argument('-v', '--verbose', action='store_true', default=False , help='verbose logging')
    args = parser.parse_args()

    # get list of hosts and host ranges from provided range of IPs --> not sure if everyone needs this functionality. If not I'll move it to the ping module
    targets = parse_hosts(args.targets)
    unpacked_targets = set()
    for target in targets:
        if isinstance(target, ipaddress.IPv4Network):
            for member in target:
                unpacked_targets.add(member)
        else:
            unpacked_targets.add(target)

    if args.port_range is None:
        print('No port range specified, using defaults.')

    # Run selected scan types (can be multiple)
    if args.discovery == 'host' or args.discovery == 'both':
        unpacked_targets = host_up.run(unpacked_targets)
    if args.discovery == 'port' or args.discovery == 'both':
        scantype_provided = 0
        if args.sT:
            scantype_provided = 1
            tcp_connect.run(unpacked_targets, args.port_range)
        if args.sU:
            scantype_provided = 1
            udp_connect.run(unpacked_targets, args.port_range)
        if args.sP:
            scantype_provided = 1
            ping_os.run(unpacked_targets, args.verbose)
        if scantype_provided == 0:
            print('Port scan requested but no scan type provided, skipping')


# Only run when called (not imported)
if __name__ == "__main__":
    main()

