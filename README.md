# UrbanRain
Network scanner originally implemented as part of CSE 4471 at The Ohio State University. This program provides a command line interface for host and port detection. It uses the sockets API to send and receive various kinds of packets.

# Installation instructions:
- Install Python (3.7 is recommended)
- Clone this repo
- `pip install ipaddress`
- `pip install netifaces`

# Usage instructions
```
usage: urban_rain.py [-h] [-p PORT_RANGE] [-sT] [-sU] [-sA] [-v] {host,port,both} targets [targets ...]

A simple python network scanner.

positional arguments:
    {host,port,both}      which type of discovery should occur
    targets               list of target ranges to scan

optional arguments:
    -h, --help            show this help message and exit
    -p PORT_RANGE, --port-range PORT_RANGE
                            dashed range of ports to scan
    -sT                   run an unprivileged TCP Connect scan
    -sU                   run an unprivileged UDP Connect scan
    -sA                   run a TCP Ack Scan
    -v, --verbose         verbose logging

Examples:
---------------------------------------------------------
    python3 urban_rain.py host 192.168.1.0-192.168.1.255
        Just host detection (without a port scan) on a dashed range of ip addresses.

    python3 urban_rain.py -p 443 both -sT 192.168.1.64/24
        Host detection then an unprivileged TCP connect scan for port 443 on a CIDR notation range of ip addresses.

    python3 urban_rain.py -p 80-81 port -sU 192.168.1.1
        Unprivileged UDP connect scan (without host detection) on ports 80 and 81 of a single ip address.

    python3 urban_rain.py port -sU 192.168.1.100-192.168.1.110
        Port scan on the default set of ports of a dashed range of ip addresses.

    python3 urban_rain.py -p 1-1023 both -sT 192.168.1.32/30 192.168.1.64-192.168.1.95 192.168.1.128
        Unprivileged TCP scan against ports 1-1023 on multiple targets of various notations.

    python3 urban_rain.py -h
        or
    python3 urban_rain.py --help
        For more help.
```