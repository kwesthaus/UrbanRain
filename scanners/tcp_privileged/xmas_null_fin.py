import cust_packet.tcp_packet

# performs either a null or an xmas scan depending on which flag is set
def run(targets, ports, flags):

    open_filtered = {}
    closed = {}
    filtered = {}

    for target in targets:
        open_filtered_ports = []
        closed_ports = []
        filtered_ports = []

        for port in ports:
            pass
