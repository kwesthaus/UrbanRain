import socket
import os
import ctypes
from scanners import tcp_connect, udp_connect

def run(targets):
    # Found online
    # Check admin rights
    try:
        # Linux check
        is_admin = os.getuid() == 0
    except AttributeError:
        #If not Linux, check Windows
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if is_admin:
        # Try an ICMP echo request (PING), TCP SYN to port 443, 
        # TCP ACK to port 80, and an ICMP timestamp request
        ICMP_HEADER = b'x08\x00\xF7x00\x00\x00\x00'
        for target in targets:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.sendto(ICMP_HEADER, (str(target), 1))
                while True:
                    try:
                        packet, address = sock.recvfrom(2048)
                        print(address)
                    except socket.error as e:
                        print(e)
    else:
        # Unprivileged
        # Use TCP connect() scan on two common ports so as to not look suspicious
        check_host_up_ports = [80, 443]
        targets_up = tcp_connect.run(targets, check_host_up_ports, print_results=False)

    print_results(targets_up)
    return targets_up

def print_results(targets_up):
    # Print results
    print('Done detecting hosts.')
    print(f'Hosts that are up: {targets_up}')
