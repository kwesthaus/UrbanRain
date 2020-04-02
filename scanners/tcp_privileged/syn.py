from scanners.tcp_privileged import privileged_tcp_scan, util
from scanners.tcp_privileged.util import Flags
from scanners.util.defaults import tcp_ports

def run(targets, port_range, print_results=True):

    # if no ports were specified, scan default TCP ports
    if port_range is None:
        port_range = tcp_ports

    # Map open, closed, and filtered ports to each target
    open_targets = {}
    closed_targets = {}
    filtered_targets = {}
    unexpected_targets = {}
    up_hosts = []

    for target in targets:
        open_ports = []
        closed_ports = []
        filtered_ports = []
        unexpected_ports = []

        for port in port_range:
            # set only SYN flag
            flags = [0, 0, 0, 0, 0, 0, 0, 1, 0]

            packet = privileged_tcp_scan.scan(target, port, flags)
            # This call only sends the SYN and receives the SYN-ACK. Normally we
            # should explicitly terminate the connection without completing
            # the three-way handshake (part 3 is an ACK packet) since this is
            # less noticeable than actually completing the handshake (which is
            # what occurs in the unprivileged TCP scan). We would do this by
            # sending a RST packet, but the kernel already does this for us
            # since we didn't tell the kernel to mark the port we sent from as
            # open.

            if packet is not None:
                protocol_number, data = util.parse_packet(packet)
                if protocol_number == 6: # then we have TCP response
                    # data = flags of TCP packet if TCP response
                    flags = data
                    if flags[Flags.SYN] and flags[Flags.ACK]:
                        open_ports.append(port)
                    elif flags[Flags.RST] and flags[Flags.ACK]:
                        closed_ports.append(port)
                    else:  # not sure what would have happened, but something weird
                        unexpected_ports.append(port)
                elif protocol_number == 1: # then we have ICMP response
                    # data = (icmp type, icmp code) if ICMP response
                    type = data[0]
                    code = data[1]
                    if (type == 3) and (code in [1, 2, 3, 9, 10, 13]):
                        filtered_ports.append(port)
                    else:  # also not sure what would have happened, but something weird
                        unexpected_ports.append(port)
                else: # unexpected protocol
                    unexpected_ports.append(port)
            else:  # no response received
                filtered_ports.append(port)

        # map target to each port and the port's status
        if open_ports or closed_ports or unexpected_ports:
            up_hosts.append(target)
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
    return up_hosts


def print_result(open, closed, filtered, unexpected):
    print('TCP SYN Stealth Scan complete.')
    print(f'Open ports by target: {open}')
    print(f'Closed ports by target: {closed}')
    print(f'Filtered ports by target: {filtered}')
    print(f'Unexpected responses by target: {unexpected}')
