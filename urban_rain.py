#!/usr/bin/env python

import argparse
import ipaddress
import os
import ctypes
from color import pcolor
from scanners import host_up, tcp_connect, udp_connect
from scanners.tcp_privileged import syn, ack, null, xmas, fin, maimon, window
from scanners.util.host_parser import parse_hosts
from attacks import syn_attack
from scanners.os_detection import os_detection
import subprocess
import socket
import re
import textwrap

# Parser for port ranges
def parseNumRange(string):
    m = re.match(r'(\d+)(?:-(\d+))?$', string)
    if not m:
        raise argparse.ArgumentTypeError(pcolor.color.ERROR + "'" + string + "' is not a range of numbers (e.g. '80-100')." + pcolor.color.CLEAR)
    start = m.group(1)
    end = m.group(2) or start
    return list(range(int(start,10), int(end,10)+1))

# Check if fragment size is multiple of 8
def fragmentSize(string):
    if not (string == "8" or string == "16"):
        raise argparse.ArgumentTypeError("Must be a value of 8 or 16.")
    return int(string)

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
        print(pcolor.color.WARNING + 'Cannot determine privileged status, assuming unprivileged' + pcolor.color.CLEAR)
        is_admin = False
    return is_admin

def valid_ipv4(address):
    octets = address.split('.')
    if len(octets) != 4:
        return None
    for item in octets:
        if not(0 <= int(item) <= 255):
            return None
    return ipaddress.IPv4Address(address)

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

                sudo python3 urban_rain.py -sO port 192.168.0.1
                    Priviledged OS detection module, returns the OS running on provided IP's
                
                sudo python3 urban_rain.py -aS port 192.168.0.1
                    Priviledged TCP SYN flood attack targeted at the provided IP

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
    parser.add_argument('-sN', action='store_true', help='run a privileged TCP Null scan')
    parser.add_argument('-sX', action='store_true', help='run a privileged TCP Xmas scan')
    parser.add_argument('-sO', action='store_true', help='run a simple os detection module')
    parser.add_argument('-aS', action='store_true', help='run a simple syn attack module')
    parser.add_argument('-sF', action='store_true', help='run a privileged TCP FIN scan')
    parser.add_argument('-sM', action='store_true', help='run a privileged TCP Maimon scan')
    parser.add_argument('-sW', action='store_true', help='run a privileged TCP Window scan')
    
    parser.add_argument('-f', '--fragmenter', type=fragmentSize, help='fragment privileged TCP scan')

    parser.add_argument('-mss', action='store_true', help='add maximum segment size TCP option')
    parser.add_argument('-sack', action='store_true', help='add SACK permitted TCP option')
    parser.add_argument('-timestamp', action='store_true', help='add timestamp TCP option')
    parser.add_argument('-no-operation', action='store_true', help='add no operation TCP option')
    parser.add_argument('-window-scale', action='store_true', help='add window scale TCP option')

    parser.add_argument('-s', '--src-addr', type=valid_ipv4, help='spoof this IPv4 address as the source of scans')

    parser.add_argument('-l', '--log',action='store_false', help='write output to a log file instead of stdout')
    parser.add_argument('-v', '--verbose', action='store_true', default=False , help='verbose logging')
    args = parser.parse_args()

    # construct option list
    optionList = []
    if args.mss:
        optionList.append(1)
    if args.sack:
        optionList.append(2)
    if args.timestamp:
        optionList.append(3)
    if args.no_operation:
        optionList.append(4)
    if args.window_scale:
        optionList.append(5)

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
        if args.port_range is None and not args.aS and not args.sO:
            print('No port range specified, using defaults.')
        scantype_provided = 0
        if args.sT:
            scantype_provided = 1
            tcp_connect.run(unpacked_targets, args.port_range,args.log)
        if args.sU:
            scantype_provided = 1
            udp_connect.run(unpacked_targets, args.port_range, args.log)
        if args.sS:
            scantype_provided = 1
            if is_admin:
                syn.run(unpacked_targets, args.port_range, optionList, args.fragmenter, args.src_addr, args.log)
            else:
                print(pcolor.color.WARNING + 'TCP SYN scan requires privileges, skipping' + pcolor.color.CLEAR)
        if args.sA:
            scantype_provided = 1
            if is_admin:
                ack.run(unpacked_targets, args.port_range, optionList, args.fragmenter, args.src_addr, args.log)
            else:
                print(pcolor.color.WARNING + 'TCP ACK scan requires privileges, skipping' + pcolor.color.CLEAR)
        if args.sN:
            scantype_provided = 1
            if is_admin:
                null.run(unpacked_targets, args.port_range, optionList, args.fragmenter, args.src_addr, args.log)
            else:
                print(pcolor.color.WARNING + 'TCP NULL scan requires privileges, skipping' + pcolor.color.CLEAR)
        if args.sX:
            scantype_provided = 1
            if is_admin:
                xmas.run(unpacked_targets, args.port_range, optionList, args.fragmenter, args.src_addr, args.log)
            else:
                print(pcolor.color.WARNING + 'TCP XMAS scan requires privileges, skipping' + pcolor.color.CLEAR)
        if args.sO:
            scantype_provided = 1
            if is_admin:
                os_detection.run(unpacked_targets)
            else:
                print(pcolor.color.WARNING + 'OS detection requires privileges, skipping' + pcolor.color.CLEAR)
        if args.aS:
            scantype_provided = 1
            if is_admin:
                syn_attack.run(unpacked_targets, args.src_addr)
            else:
                print(pcolor.color.WARNING + 'TCP attack requires privileges, skipping' + pcolor.color.CLEAR)
        if args.sF:
            scantype_provided = 1
            if is_admin:
                fin.run(unpacked_targets, args.port_range, optionList, args.fragmenter, args.src_addr, args.log)
            else:
                print(pcolor.color.WARNING + 'TCP FIN scan requires privileges, skipping' + pcolor.color.CLEAR)
        if args.sM:
            scantype_provided = 1
            if is_admin:
                maimon.run(unpacked_targets, args.port_range, optionList, args.fragmenter, args.src_addr, args.log)
            else:
                print('TCP Maimon Scan requires privileges, skipping')
        if args.sW:
            scantype_provided = 1
            if is_admin:
                window.run(unpacked_targets, args.port_range, optionList, args.fragmenter, args.src_addr, args.log)
            else:
                print(pcolor.color.WARNING + 'TCP Window Scan requires privileges, skipping' + pcolor.color.CLEAR)

        if scantype_provided == 0:
            print(pcolor.color.WARNING + 'Port scan requested but no scan type provided, skipping' + pcolor.color.CLEAR)

# Only run when called (not imported)
if __name__ == "__main__":
    main()

