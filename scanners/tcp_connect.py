import socket
from enum import Enum
from scanners.util.defaults import tcp_ports

def run(targets, port_range, print_results=True):
    if port_range is None:
        port_range = tcp_ports
    
    # Map targets to port lists
    open_targets = {}
    closed_targets = {}
    filtered_targets = {}
    up_hosts= []

    for target in targets:
        # New list for every target
        open_ports = []
        closed_ports = []
        filtered_ports = []

        for port in port_range:
            # Create a connection which will automatically be closed
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Shorten to reduce wasted time
                s.settimeout(2)
                port_status = get_port_status(s, target, port)
                if port_status == PortStates.OPEN:
                    open_ports.append(port)
                elif port_status == PortStates.CLOSED:
                    closed_ports.append(port)
                elif port_status == PortStates.FILTERED:
                    filtered_ports.append(port)
        
        # Save port lists for this target in the overall map
        if open_ports or closed_ports:
            up_hosts.append(target)
        if open_ports:
            open_targets[target] = open_ports
        if closed_ports:
            closed_targets[target] = closed_ports
        if filtered_ports:
            filtered_targets[target] = filtered_ports
    if print_results:
        output_ports(open_targets, closed_targets, filtered_targets)
    return up_hosts


def get_port_status(s, host, port):
    for i in range(0, 3):
        try:
            s.connect((str(host), port))
            return PortStates.OPEN
        except ConnectionRefusedError:
            return PortStates.CLOSED
        except socket.timeout:
            # Reinit socket and keep looping
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            pass
        except OSError as e:
            if e.errno == 113:
                # Scan ran on local network so OS ran ARP under the hood
                # and nothing spoke up
                return PortStates.FILTERED
            elif e.errno == 101:
                # IP is either the first or last IP of a subnet and therefore
                # is either the network identifier or broadcast address,
                # respectively.
                # These are not valid IP addresses for single hosts and cannot
                # be scanned, so skip this port.
                return PortStates.FILTERED
            else:
                print(f'Unspecified OSError: {e}')
        except socket.error as e:
            print(f'Unspecified socket error: {e}')
    # We got through three times without hitting any of the other returns,
    # so assume we aren't getting responses because it's filtered
    return PortStates.FILTERED

def output_ports(open_targets, closed_targets, filtered_targets):
    print('TCP connect() port scan complete.')
    print(f'Open ports by target: {open_targets}')
    print(f'Closed ports by target: {closed_targets}')
    print(f'Filtered ports by target: {filtered_targets}')

class PortStates(Enum):
    OPEN = 1
    CLOSED = 2
    FILTERED = 3
    UNFILTERED = 4
    OPEN_FILTERED = 5
    CLOSED_FILTERED = 6
