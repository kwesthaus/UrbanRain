import socket

def run(targets, port_range):
    # Map targets to port lists
    open_targets = {}
    closed_targets = {}
    filtered_targets = {}

    for target in targets:
        # New list for every target
        open_ports = []
        closed_ports = []
        filtered_ports = []

        for port in port_range:
            # Create a connection which will automatically be closed
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Shorten to reduce wasted time
                sock.settimeout(2)

                #TODO: just make this a loop so it's less ugly
                try:
                    sock.connect((str(target),port))
                except socket.error as e:
                    if e.__class__ == ConnectionRefusedError:
                        # Closed first time
                        closed_ports.append(port)
                    elif e.__class__ == socket.timeout:
                        # No response first time, try again to double check
                        try:
                            sock.connect((str(target),port))
                        except socket.error:
                            if e.__class__ == ConnectionRefusedError:
                                # Closed second time
                                closed_ports.append(port)
                            elif e.__class__ == socket.timeout:
                                # No response second time, record and move on
                                filtered_ports.append(port)
                        else:
                            # Connection went through second time
                            open_ports.append(port)
                else:
                    # Connection went through first time
                    open_ports.append(port)
        
        # Save port lists for this target in the overall map
        if open_ports:
            open_targets[target] = open_ports
        if closed_ports:
            closed_targets[target] = closed_ports
        if filtered_ports:
            filtered_targets[target] = filtered_ports

    # Print results
    print('Done scanning.')
    print(f'Open ports by target: {open_targets}')
    print(f'Closed ports by target: {closed_targets}')
    print(f'Filtered ports by target: {filtered_targets}')

