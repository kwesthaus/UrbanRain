# David Levine
import socket
import errno
from enum import Enum
from scanners.util.defaults import udp_ports
from color import pcolor

def run(targets, port_range,print_results=True):
    if port_range is None:
        port_range = udp_ports

    # Map targets to port lists
    open_filtered_targets = {}
    closed_targets = {}
    filtered_targets = {}

    for host in targets:
        # New list for every target
        open_filtered_ports = []
        closed_ports = []
        filtered_ports = []

        for port in port_range:
            #open up udp socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                port_status = get_port_status(s, host, port)
                if port_status == PortStates.OPEN_FILTERED:
                    open_filtered_ports.append(port)
                elif port_status == PortStates.CLOSED:
                    closed_ports.append(port)
                elif port_status == PortStates.FILTERED:
                    filtered_ports.append(port)

        if open_filtered_ports:
            open_filtered_targets[host] = open_filtered_ports
        if closed_ports:
            closed_targets[host] = closed_ports
        if filtered_ports:
            filtered_targets[host] = filtered_ports
    if print_results:
        output_ports(open_filtered_targets, closed_targets, filtered_targets)
    else: 
        log(open_filtered_targets, closed_targets, filtered_targets)


def get_port_status(s, host, port):
    try:
        # send empty packet three times since UDP does not gaurentee a response
        # and packets can be lost.
        # if all three succeed, we can consider this open/filtered
        for i in range(0,3):
            s.connect((str(host), port))
            s.send(b'')
            s.send(b'')

        return PortStates.OPEN_FILTERED
    #connection refused - this port is closed
    except ConnectionRefusedError as e:
        return PortStates.CLOSED
    # host unreachable - we got a response, but it told us that we can't talk
    # to the target
    except socket.error as e:
        if e.errno == errno.EHOSTUNREACH:
            return PortStates.FILTERED
        else:
            print(f'{pcolor.color.ERROR}Unspecified socket error: {e}{pcolor.color.CLEAR}')

def output_ports(open_filtered_targets, closed_targets, filtered_targets):
    print('UDP port scan complete.')
    print(f'Open|Filtered ports by target:')
    print(f'{pcolor.color.OPEN}{open_filtered_targets}{pcolor.color.CLEAR}')
    print(f'Closed ports by target:')
    print(f'{pcolor.color.CLOSED}{closed_targets}{pcolor.color.CLEAR}')
    print(f'Filtered ports by target:')
    print(f'{pcolor.color.WARNING}{filtered_targets}{pcolor.color.CLEAR}')
    
    
def log(open_filtered_targets, closed_targets, filtered_targets):
    log_file = open('log.txt','a')
    log_file.write('UDP port scan complete.')
    log_file.write(f'Open|Filtered ports by target: {pcolor.color.OPEN}{open_filtered_targets}{pcolor.color.CLEAR}')
    log_file.write(f'Closed ports by target: {pcolor.color.CLOSED}{closed_targets}{pcolor.color.CLEAR}')
    log_file.write(f'Filtered ports by target: {pcolor.color.WARNING}{filtered_targets}{pcolor.color.CLEAR}')

class PortStates(Enum):
    OPEN = 1
    CLOSED = 2
    FILTERED = 3
    UNFILTERED = 4
    OPEN_FILTERED = 5
    CLOSED_FILTERED = 6
