from scanners.tcp_privileged import privileged_tcp_scan, util
from scanners.tcp_privileged.util import Flags
from scanners.util.defaults import tcp_ports

# algorithm: 
    # send out probe packet with only the ACK flag set
        # If you receive an RST packet, (done)
           # then you will need to label the port as unfiltered
        # If a port doesnt respond (done)
            # label it as filtered
        # If you get ICMP error message back (type 3, code 0, 1, 2, 3, 9, 10, 13), 
            # label as filtered
def run(targets, port_range, options, fragment_size, print_results=True):

    if port_range is None:
        port_range = tcp_ports

    #Ack scan is only concerned with filtered and unfiltered packets
    filtered_targets = {}
    unfiltered_targets = {}
    unexpected_targets = {}
    up_hosts = []

    for target in targets:
        filtered_ports = []
        unfiltered_ports = []
        unexpected_ports = []

        for port in port_range:
            # set only the Ack flag
            flags = [0, 0, 0, 0, 1, 0, 0, 0, 0]

            packet = privileged_tcp_scan.scan(target, port, flags, options, fragment_size)

            if packet is not None:
                protocol_number, data = util.parse_packet(packet)
                if protocol_number == 6: # TCP response
                    # data = flags set in TCP packet
                    if data[Flags.RST]:
                        unfiltered_ports.append(port)
                    else: # not sure what would have happened here, but something weird
                        unexpected_ports.append(port)
                elif protocol_number == 1: # ICMP response
                    # data = (icmp type, icmp code) if ICMP response
                    # we need to check if an error was reported
                    packet_type = data[0]
                    code = data[1]
                    icmp_error_type = 3

                    destination_network_unreachable_code = 0
                    destination_host_unreachable_code = 1
                    destination_protocol_unreachable_code = 2
                    destination_port_unreachable_code = 3
                    network_adminstratively_prohibited_code = 9
                    host_administratively_prohibited_code = 10
                    communication_administratively_prohibited_code = 13

                    if (packet_type == icmp_error_type) and (
                        code == destination_network_unreachable_code
                        or code == destination_host_unreachable_code
                        or code == destination_protocol_unreachable_code
                        or code == destination_port_unreachable_code
                        or code == network_adminstratively_prohibited_code
                        or code == host_administratively_prohibited_code
                        or code == communication_administratively_prohibited_code
                    ):
                        filtered_ports.append(port)
                    else: # also not sure what would have happened, but something weird
                        unexpected_ports.append(port)
                else: # unexpected protocol
                    unexpected_ports.append(port)
            else:
                filtered_ports.append(port)
   
        # process scanned port information for host
        if unfiltered_ports or unexpected_ports:
            up_hosts.append(target)
        if filtered_ports:
            filtered_targets[target] = filtered_ports
        if unfiltered_ports:
            unfiltered_targets[target] = unfiltered_ports
        if unexpected_ports:
            unexpected_targets[target] = unexpected_ports

    if print_results:
        print_result(filtered_targets, unfiltered_targets, unexpected_targets)
    return up_hosts


def print_result(filtered_targets, unfiltered_targets, unexpected_targets):
    print('TCP Ack Scan complete.')
    print(f'Filtered ports by target: {filtered_targets}')
    print(f'Unfiltered ports by target: {unfiltered_targets}')
    print(f'Unexpected responses by target: {unexpected_targets}')

