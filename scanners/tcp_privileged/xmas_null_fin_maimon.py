from scanners.tcp_privileged import privileged_tcp_scan, util
from scanners.tcp_privileged.util import Flags
from scanners.util.defaults import tcp_ports

# performs either a null or an xmas scan depending on which flag is set
def run(targets, ports, flags, options, fragment_size, src_ip=None, print_results=True):

    # if no ports were specified, scan default TCP ports
    if ports is None:
        ports = tcp_ports

    open_filtered = {}
    closed = {}
    filtered = {}
    unexpected = {}
    up_hosts = []

    for target in targets:
        open_filtered_ports = []
        closed_ports = []
        filtered_ports = []
        unexpected_ports = []

        for port in ports:
            packet = privileged_tcp_scan.scan(target, port, flags, options, fragment_size, src_ip)

            if packet is not None:
                protocol_number, data = util.parse_packet(packet)
                if protocol_number == 6: # TCP response
                    # data = flags set in TCP packet
                    if data[Flags.RST]:
                        closed_ports.append(port)
                    else: # not sure what would have happened here, but something weird
                        unexpected_ports.append(port)
                elif protocol_number == 1: # ICMP response
                    # data = (icmp type, icmp code) if ICMP response
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
                open_filtered_ports.append(port)

        # process scanned port information for host
        if open_filtered_ports or closed_ports or unexpected_ports:
            up_hosts.append(target)
        if open_filtered_ports:
            open_filtered[target] = open_filtered_ports
        if closed_ports:
            closed[target] = closed_ports
        if filtered_ports:
            filtered[target] = filtered_ports
        if unexpected_ports:
            unexpected[target] = unexpected_ports

    if print_results:
        print_result(open_filtered, closed, filtered, unexpected)

    return up_hosts


def print_result(open_filtered, closed, filtered, unexpected):
    print('Scan complete.')
    print(f'Open|Filtered ports by target: {open_filtered}')
    print(f'Closed ports by target: {closed}')
    print(f'Filtered ports by target: {filtered}')
    print(f'Unexpected responses by target: {unexpected}')



