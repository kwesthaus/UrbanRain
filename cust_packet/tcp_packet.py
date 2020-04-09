import binascii
import struct
import cust_packet.util
import random

# function called by the client to create packets
# src_ip and dest_ip are expected to be the string versions of the IP they refer to
def create(src_ip, dest_ip, source_port, dest_port, flags, options):

    random.seed()

    b_options = b''
    # add options
    if options.count(1) != 0:
        # maximum segment size
        b_options += b'\x02\x04'            # Kind and length
        b_options += b'\x05\xB4'            # MSS Value
    if options.count(2) != 0:
        # SACK permitted
        b_options += b'\x04\x02'            # Kind and length
    if options.count(3) != 0:
        # timestamp
        b_options += b'\x08\x0A'            # Kind and length
        b_options += b'\x1E\x2C\x27\xCF'    # Timestamp Value
        b_options += b'\x00\x00\x00\x00'    # TS Echo Reply
    if options.count(4) != 0:
        # no operation
        b_options += b'\x01'                # Kind
    if options.count(5) != 0:
        # window scale
        b_options += b'\x03\x03'            # Kind and length
        b_options += b'\x07'                # Shift scale
    if len(b_options) % 4 != 0:
        nop_padding_length = 4*((len(b_options)//4)+1) - len(b_options)
        b_options += (b'\x01'*nop_padding_length)

    # Indicates the length of the TCP header in units of 32-bit doublewords
    header_length = 5 + len(b_options)//4

    # parse input accordingly
    b_source_port= parsePort(source_port)
    b_dest_port = parsePort(dest_port)
    b_seq_number = random.randint(0, 2**32).to_bytes(4, byteorder='big')
    b_flags_row = updateFlags(flags, header_length)

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
    packet_length = len(custom_tcp_header + b_checksum + b_urgent_pointer + b_options)
    b_packet_length = packet_length.to_bytes(2, "big")  # convert to 2-byte, big-endian hexadecimal representation
    pseudo_header = cust_packet.util.parseIP(src_ip) + cust_packet.util.parseIP(dest_ip) + reserved + protocol + b_packet_length

    checksum = chksum(pseudo_header + custom_tcp_header + b_checksum + b_urgent_pointer + b_options)
    b_checksum = checksum.to_bytes(2, "big")  # convert to 2-byte, big-endian hexadecimal representation

    # finish construction of tcp_header
    custom_tcp_header += b_checksum
    custom_tcp_header += b_urgent_pointer
    custom_tcp_header += b_options

    return custom_tcp_header


def parsePort(dest_port):
    return struct.pack("!H", dest_port)


def updateFlags(flags, header_length):
    first_flag = flags[0]
    # First nibble is left shifted 4 bits
    # Indicates the length of the TCP header in units of 32-bit doublewords
    offset_and_reserved = header_length<<4 + first_flag
    b_offset_and_reserved = offset_and_reserved.to_bytes(1, "big")
    window_size = b'\x20\x00' # A reasonable default - 8192 bytes

    # build base 2 value passed in from "flags" list
    build_int = ""
    for entry in flags[1:]:
        build_int += str(entry)

    # construct flags byte value
    i_flags = int(build_int, 2)
    byte_flags = struct.pack("!b", i_flags)
    
    # return final constructed row to the header
    return b_offset_and_reserved + byte_flags + window_size

def chksum(msg):
    checksum = 0
    for i in range(0, len(msg), 2):
        checksum += int(binascii.hexlify(msg[i : i + 2]), 16)

    # carry around
    checksum = checksum + (checksum >> 16)

    # one's complement and reduce to 16 bits
    checksum = ~checksum & 0xffff

    return checksum
