from scanners.tcp_privileged import privileged_tcp_scan, util
from scanners.tcp_privileged.util import Flags
from scanners.util.defaults import tcp_ports


def run(targets, ports, print_results=True):

    # if no ports were specified, scan the default TCP ports
    if ports is None:
        ports = tcp_ports

    # Map open, closed, and filtered ports to each target
    open_targets = {}
    closed_targets = {}
    filtered_targets = {}
    unexpected_targets = {}

    for target in targets:
        open_ports = []
        closed_ports = []
        filtered_ports = []
        unexpected_ports = []

        for port in ports:
            flags = [0, 0, 0, 0, 1, 0, 0, 0, 0]

            packet = privileged_tcp_scan.scan(target, port, flags)

            if packet is not None:
                protocol, data = util.parse_packet(packet)
                # determine if response was ICMP or TCP response
                if protocol == 6: # then TCP response
                    # data == TCP flags if TCP response
                    if data[Flags.RST]: # then RST response
                        window_field = util.parse_window(packet)
                        if window_field == 0:
                            closed_ports.append(port)
                        else:
                            open_ports.append(port)
                    else:
                        unexpected_ports.append(port)
                elif protocol == 1: # then ICMP response
                    # data = (type, code) if ICMP response
                    type = data[0]
                    code = data[1]
                    if (type == 3) and (code in [1, 2, 3, 9, 10, 13]):
                        filtered_ports.append(port)
                    else:  # also not sure what would have happened, but something weird
                        unexpected_ports.append(port)
                else: # unexpected protocol response
                    unexpected_ports.append(port)
            else: # no response, even after retransmission
                filtered_ports.append(port)

        # map target to each port and the port's status
        if open_ports:
            open_targets[target] = open_ports
        if closed_ports:
            closed_targets[target] = closed_ports
        if filtered_ports:
            filtered_targets[target] = filtered_ports
        if unexpected_ports:
            unexpected_targets[target] = unexpected_ports

    if print_results:
        print_result(open_targets, closed_targets, filtered_targets, unexpected_targets)

    return


def print_result(open, closed, filtered, unexpected):
    print('TCP Window Scan complete.')
    print(f'Open ports by target: {open}')
    print(f'Closed ports by target: {closed}')
    print(f'Filtered ports by target: {filtered}')
    print(f'Unexpected responses by target: {unexpected}')