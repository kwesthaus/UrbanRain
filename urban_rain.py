import argparse
import ipaddress
from scanners import host_up, tcp_connect, udp_connect, ping_os
from scanners.util.host_parser import parse_hosts
import socket
import re
import textwrap

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
    parser = argparse.ArgumentParser(description='A simple python network scanner.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
            ---------------------------------------------------------
                python3 urban_rain.py host 192.168.1.0-192.168.1.255
                    Just host detection (without a port scan) on a dashed range of ip addresses.
            
                python3 urban_rain.py -p 443 both -sT 192.168.1.64/24
                    Host detection then an unprivileged TCP connect scan for port 443 on a CIDR notation range of ip addresses.
                
                python3 urban_rain.py -p 80-81 port -sU 192.168.1.1
                    Unprivileged UDP connect scan (without host detection) on ports 80 and 81 of a single ip address.
                
                python3 urban_rain.py port -sU 192.168.1.100-192.168.1.110
                    Port scan on the default set of ports of a dashed range of ip addresses.

                python3 urban_rain.py -p 1-1023 both -sT 192.168.1.32/30 192.168.1.64-192.168.1.95 192.168.1.128
                    Unprivileged TCP scan against ports 1-1023 on multiple targets of various notations.
                
                python3 urban_rain.py -h
                    or
                python3 urban_rain.py --help
                    For more help.
            '''))
    parser.add_argument('discovery', choices=['host', 'port', 'both'], help='which type of discovery should occur')
    parser.add_argument('targets',  nargs='+', help='list of target ranges to scan')
    parser.add_argument('-p', '--port-range', type=parseNumRange, help='dashed range of ports to scan')
    parser.add_argument('-sT', action='store_true', help='run an unprivileged TCP Connect scan')
    parser.add_argument('-sU', action='store_true', help='run an unprivileged UDP Connect scan')
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

    # Run selected scan types (can be multiple)
    if args.discovery == 'host' or args.discovery == 'both':
        unpacked_targets = host_up.run(unpacked_targets)
    if args.discovery == 'port' or args.discovery == 'both':
        if args.port_range is None:
            print('No port range specified, using defaults.')
        scantype_provided = 0
        if args.sT:
            scantype_provided = 1
            tcp_connect.run(unpacked_targets, args.port_range)
        if args.sU:
            scantype_provided = 1
            udp_connect.run(unpacked_targets, args.port_range)
        if scantype_provided == 0:
            print('Port scan requested but no scan type provided, skipping')


# Only run when called (not imported)
if __name__ == "__main__":
    main()

