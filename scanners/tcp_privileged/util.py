import binascii
from enum import Enum


def parse_packet(packet):
    response_bytes = binascii.hexlify(packet)
    protocol = response_bytes[18:20]  # based on format of IPv4 packet, parse protocol number for upper-layer protocol
    protocol_number = int(protocol, 16) # convert hexadecimal string into int

    transport_layer_data_start = calc_transport_layer_data_start(response_bytes) # calculate end of ip header to find tcp segment

    if protocol_number == 6:
        data = parse_tcp(response_bytes, transport_layer_data_start)
    elif protocol_number == 1:
        data = parse_icmp(response_bytes, transport_layer_data_start)
    else:  # protocol is not what is expected, so we don't know how to parse it
        data = None
    return protocol_number, data


def parse_icmp(response_bytes, icmp_data_start):
    # first byte is the type field of icmp header
    type = response_bytes[icmp_data_start: icmp_data_start + 2]
    type_number = int(type, 16) # convert from hexadecimal string (base-16) to int

    # second byte is code field of icmp header
    code = response_bytes[icmp_data_start + 2: icmp_data_start + 4]
    code_number = int(code, 16) # parse hexadecimal string (base-16) to int

    return type_number, code_number


def parse_tcp(response_bytes, tcp_segment_start):

    # calculate beginning of reserved field in the tcp header which can be used to find the tcp segment flags
    reserved_field_offset = 25
    first_flag_offset = tcp_segment_start + reserved_field_offset

    flags_and_reserved_fields_hex_digits = response_bytes[first_flag_offset: first_flag_offset + 3]
    flags_and_reserved_fields_int = int(flags_and_reserved_fields_hex_digits, 16)  # convert to int
    flags_and_reserved_fields_list = [int(x) for x in f'{flags_and_reserved_fields_int:012b}']  # convert to binary list
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

def calc_transport_layer_data_start(response_bytes):
    # Source for info about format of IPv4 datagram: https://electronicspost.com/ipv4-datagram-format/
    # (32 / 4) in calculation is because the length recorded in the header is the number of 32-bit words in the ip header,
    # but the response has been parsed into hexadecimal digits that are 4 bits each
    return int(response_bytes[1:2], 16) * (32 // 4)

# this function assumes that packet is a IP packet whose upper-layer protocol is TCP
# the function will return the value of the window field of the packet
def parse_window(packet):
    response_bytes = binascii.hexlify(packet)

    transport_layer_data_start = calc_transport_layer_data_start(response_bytes)

    window_field_offset = transport_layer_data_start + 28 # offset in nibbles
    window_field_size = 4  # length in nibbles
    hex_window_field = response_bytes[window_field_offset: window_field_offset + window_field_size]

    return int(hex_window_field, 16) # convert hexadecimal string to integer


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
