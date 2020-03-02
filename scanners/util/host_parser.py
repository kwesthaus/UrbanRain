import ipaddress

# Parse for hosts to scan
# Each item in the targets list should use exactly one of the following mutually exclusive formats:
# specification of exactly one host,
# <start_host_ip>-<end_host_ip> for a range a hosts
# returns a list of all host IPs to scan
def parse_hosts(targets):
    # subnet = re.compile(r"(?:\d{1,3}\.|\*\.){3}(?:\d{1,3}|\*)\\\d")
    list_of_hosts = []
    for target in targets:
        if '-' in target:  # then we have a dash range of hosts being requested
            start_host, end_host = target.split('-')
            list_of_hosts.extend(process_range(start_host, end_host))
        elif '/' in target: # then we have a CIDR range of hosts being requested
            list_of_hosts.append(ipaddress.IPv4Interface(target).network)
        else: # we have just a single token to parse (which may specify multiple hosts using wildcard notation)
            host_bytes = target.split('.')
            if (len(host_bytes) != 4):
                print(f'\'{target}\' cannot be interpreted as an IPv4 host')
                exit(-1)
            list_of_hosts.append(target)
    return list_of_hosts

# returns all the IP addresses referenced by a range of IPv4 addresses starting at start_host and ending at end_host
def process_range(start_host, end_host):
    # split start and end of range into a list of 4 numbers representing the 4 bytes in the ipv4 addresses
    start_host_bytes = start_host.split('.')
    end_host_bytes = end_host.split('.')
    specified_range = []

    if (len(start_host_bytes) == len(end_host_bytes) == 4): # ipv4 addresses should contain 4 bytes each
        start_first_byte, start_second_byte, start_third_byte, start_fourth_byte = int(start_host_bytes[0]), int(
            start_host_bytes[1]), int(start_host_bytes[2]), int(start_host_bytes[3])
        end_first_byte, end_second_byte, end_third_byte, end_fourth_byte = int(end_host_bytes[0]), int(
            end_host_bytes[1]), int(end_host_bytes[2]), int(end_host_bytes[3])

        first_iteration = True
        while start_first_byte < end_first_byte:
            if first_iteration:
                new_additions = only_change_fourth_byte(start_first_byte, start_second_byte, start_third_byte, start_fourth_byte)
                specified_range.extend(new_additions)
                new_additions = only_change_third_fourth_bytes(start_first_byte, start_second_byte, start_third_byte)
                specified_range.extend(new_additions)
                new_additions = only_change_second_third_fourth_bytes(start_first_byte, start_second_byte)
                specified_range.extend(new_additions)
                first_iteration = False
            else:
                new_additions = [create_ip_address(start_first_byte, second_byte, third_byte, fourth_byte) for
                                 second_byte in range(0, 256) for third_byte in range(0, 256)
                                 for fourth_byte in range(0, 256)]
                specified_range.extend(new_additions)
            start_first_byte += 1

        # at this point, start_first_byte == end_first_byte
        while start_second_byte < end_second_byte:
            if first_iteration:
                new_additions = only_change_fourth_byte(start_first_byte, start_second_byte, start_third_byte, start_fourth_byte)
                specified_range.extend(new_additions)
                new_additions = only_change_third_fourth_bytes(start_first_byte, start_second_byte, start_third_byte)
                specified_range.extend(new_additions)
                first_iteration = False
            else:
                new_additions = [create_ip_address(start_first_byte, start_second_byte, third_byte, fourth_byte) for
                                 third_byte in range(0, 256) for fourth_byte in range(0, 256)]
                specified_range.extend(new_additions)
            start_second_byte += 1

        # now, start_second_byte == end_second_byte
        while start_third_byte < end_third_byte:
            if first_iteration:
                new_additions = only_change_fourth_byte(start_first_byte, start_second_byte, start_third_byte, start_fourth_byte)
                specified_range.extend(new_additions)
                first_iteration = False
            else:
                new_additions = [create_ip_address(start_first_byte, start_second_byte, start_third_byte, fourth_byte)
                                 for fourth_byte in range(0, 256)]
                specified_range.extend(new_additions)
            start_third_byte += 1

        # now start_third_byte == end_third_byte
        if first_iteration:
            new_additions = [create_ip_address(start_first_byte, start_second_byte, start_third_byte, fourth_byte)
                             for fourth_byte in range(start_fourth_byte,
                                                      end_fourth_byte + 1)]  # +1 since ranges don't include endpoint in python
            specified_range.extend(new_additions)
            first_iteration = False
        else:
            new_additions = [create_ip_address(start_first_byte, start_second_byte, start_third_byte, fourth_byte)
                             for fourth_byte in
                             range(0, end_fourth_byte + 1)]  # +1 since ranges don't include endpoint in python
            specified_range.extend(new_additions)
    else:
        print(start_host + '-' + end_host + 'cannot be interpreted as a range of IPv4 hosts')
        exit(-1)
    return specified_range

def only_change_fourth_byte(start_first_byte, start_second_byte, start_third_byte, start_fourth_byte):
    return [create_ip_address(start_first_byte, start_second_byte, start_third_byte, fourth_byte)
                                 for fourth_byte in range(start_fourth_byte, 256)]

def only_change_third_fourth_bytes(start_first_byte, start_second_byte, start_third_byte):
    return [create_ip_address(start_first_byte, start_second_byte, third_byte, fourth_byte)
     for third_byte in range(start_third_byte + 1, 256) for fourth_byte in range(0, 256)]

def only_change_second_third_fourth_bytes(start_first_byte, start_second_byte):
    return [create_ip_address(start_first_byte, second_byte, third_byte, fourth_byte)
     for second_byte in range(start_second_byte + 1, 256) for third_byte in range(0, 256)
     for fourth_byte in range(0, 256)]


# given strings representing each of the four bytes of an IPv4 address, convert those bytes into the corresponding
# IPv4 address
def create_ip_address(first, second, third, fourth):
    first_byte, second_byte, third_byte, fourth_byte = str(first), str(second), str(third), str(fourth)
    next_ip_address = first_byte + '.' + second_byte + '.' + third_byte + '.' + fourth_byte
    return ipaddress.ip_address(next_ip_address)