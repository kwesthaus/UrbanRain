## Knowledge Base

### Goals of a Network Scanner:
- Find hosts our packets can reach
- Find open ports on those hosts
- Identify the services and operating system (OS) on those ports/hosts
- Evade firewall and IDS detection/alerts

### Protocol Layers
Networking relies on protocol layers. Data being sent is "wrapped" inside a packet for a protocol, which in turn is wrapped by a packet for a lower level protocol, and so on until the final packet, which at this point looks like a Matryoshka doll, is actually sent across the network. This wrapping is commonly called encapsulation. The information contained in the packet at each protocol layer helps the sent data to be routed through the internet and eventually end up at the right place. When the packet reaches its final destination, the various protocol layers are stripped off in reverse order they were encapsulated, and the original data sent is delivered to whatever application is waiting to process it at the receiving end.

There are [many different ways to categorize the different protocol layers](https://en.wikipedia.org/wiki/Internet_protocol_suite#Layer_names_and_number_of_layers_in_the_literature), the most common two being the TCP/IP Model and the OSI Model. You don't need to become an expert on these models to implement a network scanner. Just know that lower level protocols encapsulate higher level ones, and that each protocol follows a packet specification which describes how the bytes should be laid out and how to interpret them. 

Protocol layers relevant to this project (from lowest to highest) are:

- **Data Link Layer (OSI Model)/Link Layer (TCP/IP Model).** We don't really touch the packets at this level for the network scanner, but it's still useful to know. Technically the protocol at this level depends on your network setup, but in most cases Ethernet Frames are being used. If you've ever seen a MAC address (usually written in the format 00:11:22:DD:EE:FF), those are used at this layer. Each physical network connector aka NIC (like an ethernet port) has one MAC address associated with it. This protocol has a `type` field which specifies the protocol used at the next layer up.
- **Network Layer (OSI Model)/Internet Layer (TCP/IP Model).** The most relevant protocols for a network scanner are IPv4 and IPv6. The header for the packet at this layer specifies the source (`src`) and destination (`dest`) address, which you might see referred to as an IP address (usually in the format 123.123.123.123). Usually, 1 IP address is associated with 1 computer (which may be called a host or a target by a network scanner). Again, this protocol has a field which specifies the protocol used at the next layer up (usually in the `protocol` or `hop-by-hop next header` field).
- **Transport Layer (both models).** TCP, UDP, and ICMP are the protocols of interest for this layer. The familiar concept of ports applies to this layer. Port numbers are usually used to specify which application you want to communicate with; that is, a specific port number is tied to a specific application listening on it. TCP includes `port`, `sequence #`, `flags`, and `options` fields which hold various information that comes in handy for network scanning. UDP includes `port` information. ICMP packets usually show up when something went wrong with an IP packet, like we tried to talk to a destination address that we're not allowed to. You can tell what happened by looking at the `type` and `code` fields of an ICMP packet. 

It's useful to have the packet structure up for reference while you're writing processing code. The packet structure has changed over time through various RFCs, so a good up-to-date resource is usually Wikipedia. Here are the packet structures for [IPv4](https://en.wikipedia.org/wiki/IPv4#Packet_structure) and [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure).

### Port Responses
Network scanning at its most basic level is just sending packets to a destination and seeing what kind of response we get back. This mostly happens at the transport layer (i.e. we send packets to a TCP or UDP port on a specific host) and we sometimes manually change information at lower levels. There are several possibilities for what a packet response from a scanned host tells us about the host and the applications it is running. Possible results include:
- **open:** the host can be reached and there is an application accepting connections on that port. We know because we got a positive response, i.e. a packet that said so.
- **closed:** the host can be reached, but either the application on that port isn't accepting connections, or there is no application listening on that port. We know because we got a negative response.
- **filtered:** the host can't be reached. We know because either something in the way blocked our path and sent back a packet saying so (this is where ICMP comes up) or we got no response and we should have for either a positive (open port) or negative (closed port) response.
- **unfiltered:** the host can be reached and we got a response back, but the response packet doesn't tell us if the port is open or closed.
- **open|filtered:** we didn't get a response back, which for this protocol only rules out the port being closed (as we would have received a response then).
- **closed|filtered:** we didn't get a response back, which for this protocol only rules out the port being open (as we would have received a response then).

### Sending Scans in Python
There are multiple ways to send packets in python, which come with a variety of abilities and tradeoffs.
- **OS cmdline.** Run a separate program already installed on the OS which already sends packets of interest and parse its output. This is the strategy used by our network scanner for sending PING packets when not called with superuser privileges because crafting and sending our own PING packets from python requires superuser access, but the `ping` utility is often available to unprivileged users.
- **OS sockets API.** This is the most common way to provide data, have it encapsulated by lower level protocols for you, send it to the desired target, and receive any packets that the target sends in response. This API can be accessed by importing the `socket` library, which is a python wrapper for the real sockets API exposed by the OS. To send packets, you need to make a "socket", which serves as a mailbox you can place your packets in and have them sent for you as well as collect responses from. This involves a call to `socket()` with three parameters. A great resource for the details of these parameters is [the relevant linux manpage](http://man7.org/linux/man-pages/man2/socket.2.html). Using this API, you can send:
    - Data to be wrapped and sent via TCP (unprivileged). Relevant flags: `socket.AF_INET`, `socket.SOCK_STREAM`
    - Data to be wrapped and sent via UDP (unprivileged). Relevant flags: `socket.AF_INET`, `socket.SOCK_DGRAM`
    - A raw TCP packet to be wrapped and sent via IP. This allows manually setting the TCP flags and other options, which in turn allows crafting a SYN scan or flood attack. Relevant flags: `socket.AF_INET`, `socket.SOCK_RAW`
    - A raw IP packet to be wrapped and sent via Ethernet. This allows spoofing of IP addresses. Relevant flags: either (`socket.AF_INET`, `socket.SOCK_RAW`, and `socket.IPPROTO_TCP` with a call to setsockopt(`socket.IP_HDRINCL`)) or (`socket.AF_INET`, `socket.SOCK_RAW`, and `socket.IPPROTO_RAW`)
    - A raw Ethernet packet. This allows spoofing of MAC addresses. Relevant flags: `socket.AF_PACKET` and `socket.SOCK_RAW` with a call to bind(`interface`)

Key references:
- [https://realpython.com/python-sockets/](https://realpython.com/python-sockets/)
- [https://www.binarytides.com/raw-socket-programming-in-python-linux/](https://www.binarytides.com/raw-socket-programming-in-python-linux/)
- [https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/](https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/)
- [https://toastersecurity.blogspot.com/2015/12/tcp-103-port-scanning-with-scapy.html](https://toastersecurity.blogspot.com/2015/12/tcp-103-port-scanning-with-scapy.html)
- [ip(7) - Linux manual page](http://man7.org/linux/man-pages/man7/ip.7.html)
- [raw(7) - Linux manual page](http://man7.org/linux/man-pages/man7/raw.7.html)
- [socket - python library documentation](https://docs.python.org/3/library/socket.html)

### Socket Details
There's a whole discussion about what the term "socket" refers to at the kernel level and as used by the Berkley sockets API (see [this](https://networkengineering.stackexchange.com/questions/54344/why-is-a-tcp-socket-identified-by-a-4-tuple)), but essentially a socket is tied to a port and IP address for your computer. When you make a connection, it is also tied to a specific port and IP of the computer on the other end of the connection. There are many socket functions that control what a socket is tied to and what data it sends, which you can learn by reading the various Linux man pages (start at the ones listed above and follow links to your heart's content).

TCP usually uses connections and UDP doesn't. When calling `connect()` on a TCP (`SOCK_STREAM`) socket, the OS sends packets for you to set up the connection with the socket on the remote host, and you can then just call `send()` and `recv()` to transfer data. A UDP (`SOCK_DGRAM`) socket usually skips `connect()` and just uses `sendto()`, which gets passed additional parameters for the socket to send to, and `recvfrom()`, which returns additional info about the socket that sent the packet you just received. However, you CAN call `connect()` on a `SOCK_DGRAM` socket. It will NOT send packets to the socket on the other side of the connection like a `SOCK_STREAM` socket would, but it does make it so you can use `send()` and `recv()` and just get packets to/from the host you are interested in. In fact, you can do the same thing for a raw socket (`SOCK_RAW`) as well.

On Linux, you can declare a raw socket and specify the protocol as `IPPROTO_TCP` to send a TCP packet. You would be able to do the same on Windows, except that Microsoft has chosen to disable this functionality ([source](https://docs.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2)), probably because you can use connect() instead and raw sockets for TCP was getting abused by malware.

You can use many different values to specify the IP protocol (the third `socket()` parameter), including 0, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, and IPPROTO_RAW. When 0 or IPPROTO_IP are specified, the OS tries to use the default protocol for the socket type, so it will work for `SOCK_STREAM` or `SOCK_DGRAM` but not `SOCK_RAW`. You can use IPPROTO_IP or IPPROTO_UDP for `SOCK_STREAM` and `SOCK_DGRAM` sockets respectively. When using `IPPROTO_RAW`, you tell the OS not to wrap your packets in an IP packet because your code will be providing the entire IP packet itself. However, the OS will do some things for you automatically, making it easier for you to craft a packet. This includes setting the checksum, setting the source IP when it is left as all NULL bytes, setting the packet ID when it is left as all NULL bytes, and setting the total length field.

One advantage of providing the whole IP packet is that it allows you to provide a fake value for the src IP address field, which makes it look like the scan is coming from somewhere else. However, networking equipment along the way may realize the IP is wrong and drop the packet. Also, you shouldn't expect a response, because the host will try to send responses back to that false IP, which isn't you. Because of this, IP spoofing is more useful for another task you can achieve by writing raw sockets, which uses very similar code to a SYN scan. SYN packets are normally used to initiate a connection, so when a host receives them it will allocate a structure for the connection info. If you continually send SYN packets over a socket but don't follow up with any of the connections, you may be able to overwhelm the host at the other end. This is called a SYN flood, and while it doesn't directly fall under network scanning, the implementation code is similar enough and has enough security implications that it is worth bringing up.

Sockets have associated structures with them in the OS which contain options. You can interact with these options by calling `getsockopt()` and `setsockopt()`. When calling `setsockopt()`, you specifcy the protocol layer you are setting the option for. Setting the `IP_HDRINCL` option at the `IPPROTO_IP` level is another way to tell the OS that you will be providing whole IP packets. You can call socket functions to specifically choose the local port for your socket, or you can let one get randomly assigned to you, and if you want to know it you can check with `getsockname()`.

Ports 1-1023 are usually for privileged processes, and an OS usually has a designated port range to pull from when establishing unprivileged sockets. Currently, ports 49152-65535 are used on Windows and OS X while ports 32768-65535 are used for Linux.

Note that if you use `SOCK_RAW` to send raw TCP packets and do not tell the OS which port you are expecting a response on, the OS may automatically send a RST packet back to the host when the host responds ([source](https://stackoverflow.com/questions/110341/tcp-handshake-with-sock-raw-socket)), killing your connection attempt (which might be desired for a SYN scan, but not if you want to actually establish a connection).

You should also keep in mind what IP addresses are valid on a subnet so that you understand the errors or strange results your network scanner gets back if you try to scan the network identifier or broadcast address. See [this link](https://serverfault.com/questions/10985/is-x-y-z-0-a-valid-ip-address).

Some TCP fields need to have valid values in order to receive successful responses or avoid an IDPS alert. [This page](https://stackoverflow.com/questions/10452855/tcp-sequence-number) and [this page](https://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/) specifiy how to set the sequence number field properly.

### Scan Techniques
Different techniques send different packets, expect different responses, and require different privilege levels. In turn, these different techniques can tell you different valuable information about the host you scan. The most common scan techniques (and those implemented by this repo) are shown below, along with how you can programatically tell what kind of response you got. Nmap provides more detail on these scans [here](https://nmap.org/book/man-port-scanning-techniques.html). 

Unprivileged:
- **TCP connect():**
    - Exception raised for a timeout. Under the hood, this means no response was received. **filtered**
    - Exception raised for a refused connection. Under the hood, this means a negative response was received (a packet with RST/ACK). **closed**
    - No error. The connection was successful. Under the hood, this means a positive response was received (a packet with SYN/ACK), and our OS completes the connection (a packet with SYN). **open**
- **UDP connect():**
    - You can use `sendto` immediately upon creating the socket, but using `connect` allows you to get some negative responses.
    - The first packet should always send successfully.
    - The second packet should produce various results upon trying to send:
        - Exception raised for connection refused. Under the hood, we got an ICMP response telling us so. **closed**
        - Exception raised for no route to host. Under the hood, we got an ICMP response telling us so. **filtered**
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

### Service/Version and OS Detection
Nmap provides `nmap-services-db` and `nmap-os-db` which we can reference to fingerprint open ports and reachable hosts. This allows us to determine what kind of software the host is running (e.g. this port is running an nginx http server). See [https://nmap.org/book/man-version-detection.html](https://nmap.org/book/man-version-detection.html) and [https://nmap.org/book/man-os-detection.html](https://nmap.org/book/man-os-detection.html).

### Firewall and IDPS Evasion
Some scans are more suspicious and likely to raise alerts than others, and some are more likely to make it through a firewall. The most used technique here is fragmentation. Though TCP packets are usually able to fit entirely in an IP packet, you're allowed to split it between multiple IP packets if needed. We can craft small IP packets to force this to happen. Some IDPS systems reconstruct packets one at a time to make sure all of the fields are valid, but do not handle fragmentation because that would involve checking data fields across multiple packets. Nmap has a good page describing some of these tactics at [https://nmap.org/book/man-bypass-firewalls-ids.html](https://nmap.org/book/man-bypass-firewalls-ids.html).

### Github Workflow References
- [Git - Basic Branching and Merging](https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging)
- [Git Feature Branch Workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow)

### Other Helpful Python Libraries
- [python argparse](https://docs.python.org/3.8/library/argparse.html)
- [python ipaddress](https://docs.python.org/3/library/ipaddress.html)

## Helpful Tools
- [Nmap](https://github.com/nmap/nmap) is the de facto tool for network scanning, we can benchmark our success based on them.
- [Wireshark](https://www.wireshark.org/index.html#aboutWS) allows you to see the actual packets your network scanner or Nmap is sending for a scan and is oftentimes even easier to use than reading source code to figure out Nmap's strategy.

