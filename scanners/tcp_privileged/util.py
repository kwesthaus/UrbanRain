import binascii
from enum import Enum

def parse_packet(packet):
    response_bytes = binascii.hexlify(packet)
    # Source for info about format of IPv4 datagram: https://electronicspost.com/ipv4-datagram-format/
    # (32 / 4) in calculation is because the length recorded in the header is the number of 32-bit words in the ip header,
    # but the response has been parsed into hexadecimal digits that are 4 bits each
    tcp_segment_start = int(response_bytes[1:2], 16) * (32 // 4)  # calculate end of ip header to find tcp segment

    # calculate beginning of reserved field in the tcp header which can be used to find the tcp segment flags
    reserved_field_offset = 25
    first_flag_offset = tcp_segment_start + reserved_field_offset

    flags_and_reserved_fields_hex_digits = response_bytes[first_flag_offset : first_flag_offset + 3]
    flags_and_reserved_fields_int = int(flags_and_reserved_fields_hex_digits, 16)  # convert to int
    flags_and_reserved_fields_list = [int(x) for x in f'{flags_and_reserved_fields_int:012b}'] # convert to binary list
    # isolate flags
    flags = {}
    flags[Flags.NS] = flags_and_reserved_fields_list[3]
    flags[Flags.CWR] = flags_and_reserved_fields_list[4]
    flags[Flags.ECE] = flags_and_reserved_fields_list[5]
    flags[Flags.URG] = flags_and_reserved_fields_list[6]
    flags[Flags.ACK] = flags_and_reserved_fields_list[7]
    flags[Flags.PSH] = flags_and_reserved_fields_list[8]
    flags[Flags.RST] = flags_and_reserved_fields_list[9]
    flags[Flags.SYN] = flags_and_reserved_fields_list[10]
    flags[Flags.FIN] = flags_and_reserved_fields_list[11]

    return flags

class Flags(Enum):
    NS = 0
    CWR = 1
    ECE = 2
    URG = 3
    ACK = 4
    PSH = 5
    RST = 6
    SYN = 7
    FIN = 8
