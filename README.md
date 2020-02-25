# UrbanRain
Network scanner originally implemented as part of CSE 4471 at The Ohio State University.

## Background Info

### Goals of a Network Scanner:
- Find hosts our packets can reach
- Find open ports on those hosts
- Identify the services and operating system (OS) on those ports/hosts
- Evade firewall and IDS detection or alerts

### Protocol Layers
Networking relies on protcol layers. Each protocol follows a packet specification and encapsulates packets for higher layers. Protocol layers relevant to this project (from lowest to highest) are:
    
2. **Data Link Layer.** In this case, the ethernet protocol is used. This protocol has a `type` field which specifies the protocol used at the network layer.
3. **Network Layer.** In this case, IPv4 and IPv6 are important. The header for the packet at this layer specifies src and dest address. The field specifying the protocol used at the transport layer is sometimes in the `protocol` field and sometimes in the `hop-by-hop next header` field.
4. **Transport Layer.** ICMP, TCP, and UDP are the protocols of interest for this layer. ICMP contains `type` and `code` information. TCP includes `port`, `sequence #`, `flags`, and `options` information. UDP includes `port` information.

### Port Responses
There are several possibilities for what a packet response from a scanned host tells us. Possible results include:
- **open:** the host can be reached and there is an application accepting connections on that port. We know because we got a positive response.
- **closed:** the host can be reached, but either the application on that port isn't accepting connections, or there is no application listening on that port. We know because we got a negative response.
- **filtered:** the host can't be reached. We know because either something in the way blocked our path or we got no response and we should have for either a positive or negative response.
- **unfiltered:** the host can be reached and we got a response back, but the response doesn't tell us if it was postive or negative.
- **open|filtered:** we didn't get a response back, which for this protocol only rules out being closed (as we would have received a response then).
- **closed|filtered:** we didn't get a response back, which for this protocol only rules out being open (as we would have received a response then).

### Sending Scans in Python
There are numerous ways to send packets in python, which come with a variety of abilities and tradeoffs.
- **OS cmdline.** Run another program which already sends packets of interest. This is most helpful for PING packets as sending our own from python requires superuser access, but the `ping` utility is often available to unprivileged users.
- **OS sockets API.** This is the most common way to provide data, have it encapsulated by lower level protocols for you, then send it to the desired target. This includes:
    - Data to be wrapped and sent via TCP (unprivileged). Relevant flags: `socket.AF_INET`, `socket.SOCK_STREAM`
    - Data to be wrapped and sent via UDP (unprivileged). Relevant flags: `socket.AF_INET`, `socket.SOCK_DGRAM`
    - A raw TCP packet to be wrapped and sent via IP. This allows crafting a SYN scan or flood attack. Relevant flags: `socket.AF_INET`, `socket.SOCK_RAW`
    - A raw IP packet to be wrapped and set via Ethernet. This allows spoofing of IP addresses. Relevant flags: either (`socket.AF_INET`, `socket.SOCK_RAW`, and `socket.IPPROTO_TCP` with a call to setsockopt(`socket.IP_HDRINCL`)) or (`socket.AF_INET`, `socket.SOCK_RAW`, and `socket.IPPROTO_RAW`)
    - A raw Ethernet packet. This allows spoofing of MAC addresses. Relevant flags: `socket.AF_PACKET` and `socket.SOCK_RAW` with a call to bind(`interface`)

Key references:
- [https://realpython.com/python-sockets/](https://realpython.com/python-sockets/)
- [https://www.binarytides.com/raw-socket-programming-in-python-linux/](https://www.binarytides.com/raw-socket-programming-in-python-linux/)
- [https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/](https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/)
- [https://toastersecurity.blogspot.com/2015/12/tcp-103-port-scanning-with-scapy.html](https://toastersecurity.blogspot.com/2015/12/tcp-103-port-scanning-with-scapy.html)
- [ip(7) - Linux manual page](http://man7.org/linux/man-pages/man7/ip.7.html)
- [raw(7) - Linux manual page](http://man7.org/linux/man-pages/man7/raw.7.html)


The following flags are good to know.
- `IPPROTO_IP`: We are setting an option at the IP level.
- `IPPROTO_TCP` or `IPPROTO_UDP`: Ensure that we have the proper value in the `protocol` field of the IP header, regardless of whether the packet is of type `SOCK_STREAM`, `SOCK_DGRAM`, or `SOCK_RAW`.

Even when `IP_HDRINCL` is set (and we are providing our own IP packet header), some info in the header is still modified for us. This includes:
- The `checksum` field (which makes it for us easy since we don't have to calculate it).
- The `total length` field (which also makes it easy for us).
- The `src address` field ONLY when it is all 0s
- The `packet ID` field ONLY when it is all 0s

### Scan Techniques
Different techniques send different packets, expect different responses, and require different privilege levels.

Unprivileged:
- **TCP connect():**
    - Exception raised for a timeout. Under the hood, this means no response was received. **filtered**
    - Exception raised for a refused connection. Under the hood, this means a negative response was received (a packet with RST/ACK). **closed**
    - No error. The connection was successful. Under the hood, this means a positive response was received (a packet with SYN/ACK), and our OS completes the connection (a packet with SYN). **open**
- **UDP connect():**
    - You can use `sendto` immediately upon creating the socket, but using `connect` allows you to get some negative responses.
    - The first packet should always send successfully.
    - The second packet should produce various results upon trying to send:
        - Exception raised for connection refused. Under the hood, we got an ICMP response telling us no. **closed**
        - Exception raised for no route to host. Under the hood, we got an ICMP response telling us now. **filtered**
        - No error. Either the connection was successful or we got no response at all. **open|filtered**
- **OS cmdline `ping`:**
    - Positive output printed. **host reachable**
    - Negative output printed. **host not reachable**

Privileged (uses `socket.SOCK_RAW`):
- **TCP SYN:** Send just the first part of the TCP handshake, never complete it. Means some IDS and firewalls don't record our IP address. Possible responses:
    - Receive a SYN/ACK packet back. We send a RST packet back to break the connection. **open**
    - Receive an RST/ACK packet back. **closed**
    - No response (even after sending a second packet to make sure). **filtered**
- **TCP FIN:** Set special flags on a raw TCP packet, can produce interesting responses.
- **TCP ACK:** Set special flags on a raw TCP packet, can produce interesting responses.
- **TCP NULL:** Set special flags on a raw TCP packet, can produce interesting responses.
- **TCP XMAS:** Set special flags on a raw TCP packet, can produce interesting responses.
- **TCP Maimon:** Set special flags on a raw TCP packet, can produce interesting responses.
- **TCP Window:** Set special flags on a raw TCP packet, can produce interesting responses.
- **Manual PING:** Check [https://gist.github.com/pklaus/856268](https://gist.github.com/pklaus/856268) and [http://www.bitforestinfo.com/2018/01/code-icmp-raw-packet-in-python.html](http://www.bitforestinfo.com/2018/01/code-icmp-raw-packet-in-python.html).

Extra options:
- Launch a DOS attack by flooding TCP SYN requests and not continuing the connection.
- Spoof IP addresses.

### Service/Version and OS Detection
Nmap provides `nmap-services-db` and `nmap-os-db` which we can reference to fingerprint open ports and reachable hosts. See [https://nmap.org/book/man-version-detection.html](https://nmap.org/book/man-version-detection.html) and [https://nmap.org/book/man-os-detection.html](https://nmap.org/book/man-os-detection.html).

### Firewall and IDS Evasion
TODO: Investigate using some of the options from [https://nmap.org/book/man-bypass-firewalls-ids.html](https://nmap.org/book/man-bypass-firewalls-ids.html), such as fragmentation.

### Github Workflow References
- [Git - Basic Branching and Merging](https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging)
- [Git Feature Branch Workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow)

### Other Links
- [python argparse](https://docs.python.org/3.8/library/argparse.html)
- [python ipaddress](https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Network)
