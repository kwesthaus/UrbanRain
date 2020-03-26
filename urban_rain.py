#!/usr/bin/env python

import argparse
import ipaddress
import os
import ctypes
from scanners import host_up, tcp_connect, udp_connect
from scanners.tcp_privileged import syn, ack, null, xmas
from scanners.util.host_parser import parse_hosts
import subprocess
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

def check_admin():
    # Check admin rights
    try:
        # Linux check
        is_admin = os.getuid() == 0
    except AttributeError:
        # If not Linux, check Windows
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        # Unknown OS, cannot determine privileged status
        print('Cannot determine privileged status, assuming unprivileged')
        is_admin = False
    return is_admin

def main():

    is_admin = check_admin()

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
                
                sudo python3 urban_rain.py port -sS 192.168.1.100-192.168.1.110
                    Privileged TCP SYN port scan on the default set of ports of a dashed range of ip addresses.

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
    parser.add_argument('-sS', action='store_true', help='run a privileged TCP SYN scan')
    parser.add_argument('-sA', action='store_true', help='run a privileged TCP ACK scan')
    parser.add_argument('-sN', action='store_true', help='run a privileged TCP NULL scan')
    parser.add_argument('-sX', action='store_true', help='run a privileged TCP Xmas scan')

    parser.add_argument('-v', '--verbose', action='store_true', default=False , help='verbose logging')
    args = parser.parse_args()

    # get list of hosts and host ranges from provided range of IPs
    targets = parse_hosts(args.targets)
    unpacked_targets = set()
    # Ensure that all targets are IPv4 strings
    for target in targets:
        if isinstance(target, ipaddress.IPv4Network):
            for member in target:
                unpacked_targets.add(str(member))
        else:
            unpacked_targets.add(str(target))

    # Run selected scan types (can be multiple)
    if args.discovery == 'host' or args.discovery == 'both':
        unpacked_targets = host_up.run(unpacked_targets, is_admin)
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
        if args.sS:
            scantype_provided = 1
            if is_admin:
                syn.run(unpacked_targets, args.port_range)
            else:
                print('TCP SYN scan requires privileges, skipping')
        if args.sA:
            scantype_provided = 1
            if is_admin:
                ack.run(unpacked_targets, args.port_range)
            else:
                print('TCP ACK scan requires privileges, skipping')
        if args.sN:
            scantype_provided = 1
            if is_admin:
                null.run(unpacked_targets, args.port_range)
            else:
                print('TCP NULL scan requires privileges, skipping')
        if args.sX:
            scantype_provided = 1
            if is_admin:
                xmas.run(unpacked_targets, args.port_range)
            else:
                print('TCP XMAS scan requires privileges, skipping')
        if scantype_provided == 0:
            print('Port scan requested but no scan type provided, skipping')

# Only run when called (not imported)
if __name__ == "__main__":
    main()

