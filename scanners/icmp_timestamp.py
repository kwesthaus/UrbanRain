# Kyle Westhaus
import socket
import struct
import time

def run(targets, print_results=True):
    # According to RFC 792
    icmp_type = 13
    icmp_code = 0
    # To be replaced
    icmp_checksum = 0
    # A number that stands out
    icmp_id = 0x3713
    # A 1 in network byte order
    icmp_seq = 256
    # 0 milliseconds after midnight for all 3 4-byte fields
    timestamp_data = b'\x00'*12

    # Create packet
    header_for_calc = struct.pack('bbHHh', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    packet_for_calc = header_for_calc + timestamp_data
    icmp_checksum = calc_checksum(packet_for_calc)
    echo_header = struct.pack('bbHHh', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    echo_packet = echo_header + timestamp_data

    targets_up = set()
    for target in targets:
        # Use a raw socket so our ICMP packet is encapsulated in an IP packet
        # with the appropriate value in the protocol field
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            s.settimeout(2)
            s.sendto(echo_packet, (str(target), 1))
            try:
                recv_packet, address = s.recvfrom(1024)
            except socket.timeout:
                pass
            else:
                # Offset of ICMP header within IP packet
                recv_header = recv_packet[20:28]
                recv_type, recv_code, recv_checksum, recv_id, recv_seq = struct.unpack('bbHHh', recv_header)
                if print_results:
                    print(f'Received packet from address {address} of type: {recv_type}, code: {recv_code}, checksum: {recv_checksum}, id: {recv_id}, seq: {recv_seq}')
                # Ensure the response is intended for our ID#
                if recv_id == icmp_id:
                    targets_up.add(target)
    return targets_up

def calc_checksum(icmp_struct):
    run_sum = 0
    # Running sum of swapped-order two byte pairs
    for i in range(0, len(icmp_struct), 2):
        run_sum += (icmp_struct[i+1]*256 + icmp_struct[i])
    # End-around carry
    run_sum = run_sum + (run_sum >> 16)
    # Negate and ensure 16 bits
    run_sum = ~run_sum & 0xffff

    return run_sum
