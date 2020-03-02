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

def run(targets, verbose=False):
    op_sys = os.name
    ping_flag = False

    # iterate through targets and run the ping command
    for target in targets:
        ping_command = get_command(op_sys, target)

        # do the pinging
        print('-------------------------------------')
        with subprocess.Popen(ping_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            for line in p.stdout:
                decoded_line = line.decode("utf-8")
                if 'bytes of data' in decoded_line:
                    ping_flag = False
                if verbose:
                    # print everything
                    sys.stdout.write(decoded_line) # print() was being weird with decoded strings
                    # print(line.decode("utf-8"))
                else:
                    # only print ping statistics
                    if 'ping statistics' in decoded_line.lower():
                        ping_flag = True
                    if ping_flag:
                        sys.stdout.write(line.decode("utf-8"))


# For testing purposes
if __name__ == '__main__':
    run([ipaddress.IPv4Network('8.8.8.8'), ipaddress.IPv4Network('10.10.10.10')], verbose=False)

