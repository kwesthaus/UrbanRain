import socket
import binascii
import ipaddress
import random

from cust_packet import tcp_packet as tp, ip_packet
from scanners.util.defaults import tcp_ports
from scanners import fragment_packet

import scapy.all
from scapy.all import *

def scan(target, port, flags, options, fragment_size, src_ip=None):
    random.seed()

    if not src_ip:
        # Use scapy to figure out the interface that can get us to the target
        # Then store the IP address assigned to that interface as our source IP
        src_ip = conf.route.route(target)[1]
    # Choose a dynamic (TCP) client port. Max port number is 65536. IANA
    # and Windows specify the range as starting at 49152 while linux uses
    # 32768 as the lower bound. We choose the more restrictive of these to
    # be platform-independent.
    # We don't necessarily have to do this, but it helps the packet look
    # more legitimate so it is harder to block our scans.
    src_port = random.randint(49152, 65536)

    # create tcp_segment with source=router, dest=target, src_port=src_port, dst_port=port, flags=flags, and options=options
    tcp_segment = tp.create(src_ip, target, src_port, port, flags, options)

    # If fragment_size option is active then separate packets into fragment size.
    if fragment_size is not None:
        packet = fragment_packet.run(tcp_segment, src_ip, target, port, fragment_size)

    # Otherwise run as normal
    else:
        # Uses the common Berkeley sockets API
        # AF_INET - family is IPv4
        # SOCK_RAW - we will send packets at the IP level
        # IPPROTO_TCP - specifies transport layer packet that the IP packet will be encapsulating
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            # Specifies that the IP header will be included
            # Both for learning purposes and so that we can spoof IPs
            # This will come in handy for TCP SYN attacks and IP fragmentation
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # reduce the timeout period since we want to scan quickly
            s.settimeout(2)

            ip_id = random.randint(0, 65535)
            more_fragments = 0
            fragment_offset = 0
            # wrap tcp_segment in ip_network_packet
            ip_network_packet = ip_packet.create(tcp_segment, src_ip, target, ip_id, more_fragments, fragment_offset)
            # perform scan
            try:
                # Since this is a SOCK_RAW, connect() doesn't perform a three-way
                # handshake like it would for a normal TCP socket. Instead, this
                # makes it so that we can use send() instead of sendto() to reach
                # our target, and that when using recv() we will only get packets
                # back from our desired target.
                # If we didn't specify this, our socket would be passed EVERY IP
                # packet that our system receives.
                s.connect((str(target), port))
                s.send(ip_network_packet)
                packet = s.recv(1024)
            except socket.timeout: # retry scan
                try:
                    s.send(ip_network_packet)
                    packet = s.recv(1024)
                except socket.timeout:
                    packet = None

    return packet
