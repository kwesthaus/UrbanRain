import subprocess
import sys
import os
import ipaddress

'''
Run the ping command on a specified array of target IPs
'''

def get_command(op_sys, target):
    if op_sys == 'nt': ping_command = ['ping', f'{target}', '-4']
    elif op_sys == 'posix': ping_command = ['ping', f'{target}', '-c', '4', '-4']
    return ping_command

def run(targets, print_results=True, verbose=False):
    op_sys = os.name
    targets_up = set()
    #print_flag = False

    # iterate through targets and run the ping command
    for target in targets:
        ping_command = get_command(op_sys, target)

        # do the pinging
        with subprocess.Popen(ping_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            for line in p.stdout:
                decoded_line = line.decode("utf-8")
                if 'bytes from' in decoded_line:
                    targets_up.add(target)
                if print_results:
                    # Handles OS-specific output from the ping command
                    # "bytes from" -> posix systems
                    # "Reply from" -> nt systems
                    if 'bytes from' in decoded_line or 'Reply from' in decoded_line:
                        print_flag = False
                    if verbose:
                        # print everything
                        sys.stdout.write(decoded_line) # print() was being weird with decoded strings
                        # print(line.decode("utf-8"))
                    else:
                        # only print ping statistics
                        if 'ping statistics' in decoded_line.lower():
                            print_flag = True
                        if print_flag:
                            sys.stdout.write(line.decode("utf-8"))
    return targets_up

# For testing purposes
if __name__ == '__main__':
    run([ipaddress.IPv4Network('8.8.8.8'), ipaddress.IPv4Network('10.10.10.10')], print_results=True)

