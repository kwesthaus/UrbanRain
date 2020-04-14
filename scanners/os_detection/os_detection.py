from scapy.all import *
from scapy.layers.inet import IP, ICMP
from color import pcolor


"""
Approach:
determine the OS of the provided IP's passively by examining the ttl
field of the response from each packet. You can also detect an OS using an active
approach that requires a large database with the different fingerprint of each
possible operating system. However, this was out of the scope for our project.

Note:
ttl Windows -> 128
ttl Linux/Mac -> 64
"""


def run(targets):
    # determine if the user provided one or multiple IP's
    if (len(targets) > 0):
        for target_ip in targets:
            processOSDetection(target_ip)
    elif (len(targets) == 0):
        print(f'{pcolor.color.ERROR}No up hosts to provide OS detection for{pcolor.color.CLEAR}')


# function that receives an ip and returns the OS based on the ttl of response
def processOSDetection(ip):
    # create packet and response
    packet = IP(dst=ip)/ICMP()
    # note: timeout is set in case the ip doesn't provide a response
    response = sr1(packet, timeout=2, verbose=False)

    # parse result data and print to the client
    if response == None:
        print (f'{pcolor.color.WARNING}no response from provided IP{pcolor.color.CLEAR}')
    elif IP in response:  
        if response.getlayer(IP).ttl <= 64:
            os_result = "Unix based machine"
        else:
            os_result = "Windows based machine"

        print(ip + " is a " + os_result)

