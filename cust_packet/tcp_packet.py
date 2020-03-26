import binascii
import struct
import cust_packet.util
import random

# function called by the client to create packets
# src_ip and dest_ip are expected to be the string versions of the IP they refer to
def create(src_ip, dest_ip, source_port, dest_port, flags):

    random.seed()

    # parse input accordingly
    b_source_port= parsePort(source_port)
    b_dest_port = parsePort(dest_port)
    b_seq_number = random.randint(0, 2**32).to_bytes(4, byteorder='big')
    b_flags_row = updateFlags(flags)

    # build header
    custom_tcp_header = b_source_port             # Source Port
    custom_tcp_header += b_dest_port              # Destination port
    custom_tcp_header += b_seq_number             # Sequence Number
                                                  # - Random since we start the connection
    custom_tcp_header += b'\x00\x00\x00\x00'      # Acknowledgement Number
                                                  # - 0 since we start the connection
    custom_tcp_header += b_flags_row              # Data Offset, Reserved, Flags | Window Size

    # pause construction of tcp_header to calculate checksum

    # additional fields of tcp_header needed for checksum
    b_checksum = b'\x00\x00'
    b_urgent_pointer = b'\x00\x00'

    # calculation of checksum requires pseudo_header (which includes some elements from the IP header)
    reserved = b'\x00'
    protocol = b'\x06' # Specifies TCP as per RFC 1700
    packet_length = len(custom_tcp_header + b_checksum + b_urgent_pointer)
    b_packet_length = packet_length.to_bytes(2, "big")  # convert to 2-byte, big-endian hexadecimal representation
    pseudo_header = cust_packet.util.parseIP(src_ip) + cust_packet.util.parseIP(dest_ip) + reserved + protocol + b_packet_length

    checksum = chksum(pseudo_header + custom_tcp_header + b_checksum + b_urgent_pointer)
    b_checksum = checksum.to_bytes(2, "big")  # convert to 2-byte, big-endian hexadecimal representation

    # finish construction of tcp_header
    custom_tcp_header += b_checksum
    custom_tcp_header += b_urgent_pointer

    return custom_tcp_header


def parsePort(dest_port):
    return struct.pack("!H", dest_port)


def updateFlags(flags):
    first_flag = flags[0]
    # First nibble is 5
    # Indicates the length of the TCP header in units of 32-bit doublewords
    # 5 is the minimum value, which occurs when no TCP options are specified
    if first_flag == 0:
        offset_and_reserved = b'\x50'
    else:
        offset_and_reserved = b'\x51'
    window_size = b'\x20\x00' # A reasonable default - 8192 bytes

    # build base 2 value passed in from "flags" list
    build_int = ""
    for entry in flags[1:]:
        build_int += str(entry)

    # construct flags byte value
    i_flags = int(build_int, 2)
    byte_flags = struct.pack("!b", i_flags)
    
    # return final constructed row to the header
    return offset_and_reserved + byte_flags + window_size

def chksum(msg):
    checksum = 0
    for i in range(0, len(msg), 2):
        checksum += int(binascii.hexlify(msg[i : i + 2]), 16)

    # carry around
    checksum = checksum + (checksum >> 16)

    # one's complement and reduce to 16 bits
    checksum = ~checksum & 0xffff

    return checksum
