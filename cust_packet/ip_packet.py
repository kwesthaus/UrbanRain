# Nick Morris and Kyle Westhaus
import binascii
import struct
import sys
import ctypes
import cust_packet.util

def create(transport_layer_segment, src_ip, dest_ip, ip_id=1, more_fragments=0, fragment_offset=0):

    # store values for header fields in variables
    ip_version_header_length = b'\x45'  # IP version, Header length
    ip_tos = b'\x00'  # IP tos
    tot_len = len(transport_layer_segment) + 20  # IP total length
    tot_len = tot_len.to_bytes(2, "big")  # convert to bytes representation with big-endian interpretation

    b_ip_id = ip_id.to_bytes(2, "big")  # IP ID#

    if more_fragments:
        # Set the 3rd MSB of the high byte
        fragment_offset += 1<<13
    b_ip_fragmentation = fragment_offset.to_bytes(2, "big")  # IP fragmentation bit

    ip_ttl = b'\x40'  # IP Time to live
    transport_layer_protocol = b'\x06'  # Transport layer protocol = TCP
    checksum = b'\x00\x00'  # IP checksum
    # parse user defined packet info
    b_src_ip = cust_packet.util.parseIP(src_ip)
    b_dest_ip = cust_packet.util.parseIP(dest_ip)


    # craft IP header from variables and checksum created above
    custom_ip_header = ip_version_header_length
    custom_ip_header += ip_tos
    custom_ip_header += tot_len
    custom_ip_header += b_ip_id
    custom_ip_header += b_ip_fragmentation
    custom_ip_header += ip_ttl
    custom_ip_header += transport_layer_protocol
    custom_ip_header += checksum
    custom_ip_header += b_src_ip
    custom_ip_header += b_dest_ip

    return custom_ip_header + transport_layer_segment
