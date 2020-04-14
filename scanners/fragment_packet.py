# Ben Hiner
import socket
import random

from cust_packet.ip_packet import create
from cust_packet.tcp_packet import parsePort, updateFlags

def run(tcp_segment, src_ip, dest_ip, dest_port, bytes_per_packet):
    random.seed()

    # Uses the common Berkeley sockets API
    # AF_INET - family is IPv4
    # SOCK_RAW - we will send packets at the IP level
    # IPPROTO_TCP - specifies transport layer packet that the IP packet will be
    # encapsulating
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
        # Specifies that the IP header will be included
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(2)

        # Every group of fragmented packets should share the same ID
        # Randomly generated here so that different groups have different IDs
        ip_id = random.randint(0, 65535)

        # 1 fragment for every chunk of size bytes_per_packet and 1 for any
        # extra bytes at the end that don't make up a full chunk
        fragment_count = (len(tcp_segment)-1)//bytes_per_packet + 1
        # The Fragment Offset field in the IP header is in units of 8-byte
        # lines
        offset_lines = bytes_per_packet//8

        for fragment in range(fragment_count):
            start_byte = fragment * bytes_per_packet
            end_byte = start_byte + bytes_per_packet
            tcp_fragment = tcp_segment[start_byte:end_byte]

            # All but the last fragment should have the More Fragments bit set
            if fragment != fragment_count - 1:
                more_fragments = 1
            else:
                more_fragments = 0
            fragment_offset = fragment * offset_lines

            # Wrap TCP fragment in IP packet
            ip_network_packet = create(tcp_fragment, src_ip, dest_ip, ip_id, more_fragments, fragment_offset)
            
            # Perform scan
            try:
                # Since this is a SOCK_RAW, connect() doesn't perform a three-way
                # handshake like it would for a normal TCP socket. Instead, this
                # makes it so that we can use send() instead of sendto() to reach
                # our target, and that when using recv() we will only get packets
                # back from our desired target.
                # If we didn't specify this, our socket would be passed EVERY IP
                # packet that our system receives.
                s.connect((str(dest_ip), dest_port))
                s.send(ip_network_packet)
                packet = s.recv(1024)
            except socket.timeout: # retry scan
                try:
                    s.send(ip_network_packet)
                    packet = s.recv(1024)
                except socket.timeout:
                    packet = None

    return packet

