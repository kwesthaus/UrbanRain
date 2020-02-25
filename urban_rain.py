import argparse
import ipaddress
from scanners import tcp_connect, udp_connect, ping_os
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

    # Parseargs
    parser = argparse.ArgumentParser(description='A simple python network scanner.')
    parser.add_argument('targets', type=ipaddress.IPv4Network, help='CIDR range of targets to scan')
    parser.add_argument('-p', '--port-range', type=parseNumRange, help='range of ports to scan')
    parser.add_argument('-sT', action='store_true', help='run an unprivileged TCP Connect scan')
    parser.add_argument('-sU', action='store_true', help='run an unprivileged UDP Connect scan')
    parser.add_argument('-sP', action='store_true', help='run an unprivileged PING scan')
    args = parser.parse_args()
    
    # Run selected scan types (can be multiple)
    if args.sT:
        tcp_connect.run(args.targets, args.port_range)
    if args.sU:
        udp_connect.run(args.targets, args.port_range)
    if args.sP:
        ping_os.run(args.targets, args.port_range)

# Only run when called (not imported)
if __name__ == "__main__":
    main()

