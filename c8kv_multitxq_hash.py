import binascii
import socket
import crc32c
import ipaddress
import argparse
import sys
import itertools
import logging
import json
from copy import deepcopy
import re

# uncomment the line below to output debug messages
#logging.basicConfig(level=logging.DEBUG)

#
# Packet information:
# src address is 10.20.0.95   dst address = 10.20.0.2
# protocol is 17 (UDP) . src port = 0x66d9 dst port = 0x35
# final calculated CRC 0x91a09837
#
# Debug output messages from ucode calculating hash.
# 1. compute hash src 0x5f00140a dst 0x0200140a  << addresses read from packet as little endian
# 2. in compute hash routine src 0x5f00140a dst 0x0200140a
# 3. prot 0x00000011 u32-0 0x01110000
# 4. crc0 0x69945ecd
# 5. src>dst src u32-1 0x0a14005f normalize crc1 0xd3d1f46d. << swap to big endian src address
# 6. src>dst dst u32-2 0x0a140002 normalize crc2 0x2220ba6f. << swap to big endian dst address
# 7. src port 0x0000d966 dst port 0x00003500  << port addresses read from packet as little endian
# 8. SWAP endian src port 0x000066d9 dst port 0x00000035. << swap to big endian for manipulation This is the actual port number
# 9. u32-3 0x003566d9 final crc3 0x91a09837
#
# Python code below the src addr, dst addr, src port, and dst port are represented as big endian therefore don't need to
# do swap.  However, when calculating the crc the data must be swapped to little endian to match Intel endian (i.e little endian).
#
# Currently TCP and UDP support src and dst port, all other protocol these parameters are zero.
#
# Another example:
# 
# Packet information:
# src ip: 192.168.01.42 dst ip: 192.168.02.42
# protocol 0x32 (ESP) src port = 0x0 dst port = 0x0
# final CRC 0x66567db1
#
# buginf output from ucode:
# dst: 0x2a02a8c0 (from packet in little endian) 
# src: 0x2a01a8c0 (from packet in little endian) 
# prot: 0x00000032 (1 byte from packet) 
# dstp: 0x000030e4 (junk because no port)
# srcp: 0x0000480d (junk because no port)
# src_gt_dst 0 (the src is less than dst which mean the comparison is done in big endian)
# u32[0]: 0x01320000 (in big endian)
# u32[1]: 0xc0a8022a (swap dst to big endian)
# u32[2]: 0xc0a8012a (swap src to big endian)
# u32[3]: 0x00000000 (src and dst port are zeros)
# crc1: 0x22f81556 
# crc2: 0xde0a5ecf 
# crc3: 0x6c09efba 
# crc4: 0x66567db1 
# final crc: 0x66567db1
#
# The python code read ip address in big endian
# print debug messages from this hash code:
# u[0]: 00003201 (in little endian)
# u[1]: 2a02a8c0 (in little endian)
# u[2]: 2a01a8c0 (in little endian)
# u[3]: 00000000 
# crc u0 22f81556 - which is crc1 from ucode debug
# crc u1 de0a5ecf
# crc u2 6c09efba
# crc u3 66567db1
# crc_calc 66567db1
# This show python code generate same crc as ucode

def crc_hash(dest_ip, src_ip, prot, src_port, dst_port, mod, normalize):
    ip_dest = socket.inet_aton(str(dest_ip))
    ip_src = socket.inet_aton(str(src_ip))

    ip_dest_big = int.from_bytes(ip_dest, byteorder='big')
    ip_src_big = int.from_bytes(ip_src, byteorder='big')
    hex_str_ip_dest = '{:08x}'.format(int.from_bytes(ip_dest, byteorder='little'))
    hex_str_ip_src = '{:08x}'.format(int.from_bytes(ip_src, byteorder='little'))

    u0 = (0x1<<24) | (prot<<16)
    byte_u0 = u0.to_bytes(length = 4, byteorder='big')
    # must change u0 to little endian to match ucode intel arch. 
    hex_str_u0 = '{:08x}'.format(int.from_bytes(byte_u0, 'little'))

    if prot == 6 or prot == 17 :
        if dst_port >= src_port:
            u3 = (src_port << 16) | dst_port
        else:
            u3 = (dst_port << 16) | src_port
    else:
        u3 = 0x00000000
    # Before going into the hash u3 need to change to little endian for calculation to match intel arch.
    byte_u3 = u3.to_bytes(length = 4, byteorder="big")
    hex_str_u3 = '{:08x}'.format(int.from_bytes(byte_u3, 'little'))

    # The crc1 through crc4 show incremental crc stages similar to ucode
    # calculate and print these values to debug ucode output.
    crc1 = crc32c.crc32c(binascii.a2b_hex(hex_str_u0))

    if normalize == "TRUE" :
        # Haven't found a way to do crc in stages like ucode, for now we concat all of them together.
        if ip_dest_big > ip_src_big :
            crc_data = hex_str_u0+hex_str_ip_dest+hex_str_ip_src+hex_str_u3
            crc2 = crc32c.crc32c(binascii.a2b_hex(hex_str_ip_dest), crc1)
            crc3 = crc32c.crc32c(binascii.a2b_hex(hex_str_ip_src), crc2)
        else:
            crc_data = hex_str_u0+hex_str_ip_src+hex_str_ip_dest+hex_str_u3
            crc2 = crc32c.crc32c(binascii.a2b_hex(hex_str_ip_src), crc1)
            crc3 = crc32c.crc32c(binascii.a2b_hex(hex_str_ip_dest), crc2)
    else:
        crc_data = hex_str_u0+hex_str_ip_src+hex_str_ip_dest+hex_str_u3
        crc2 = crc32c.crc32c(binascii.a2b_hex(hex_str_ip_src), crc1)
        crc3 = crc32c.crc32c(binascii.a2b_hex(hex_str_ip_dest), crc2)


    crc4 = crc32c.crc32c(binascii.a2b_hex(hex_str_u3), crc3)

    logging.debug('u[0]: {} u[1]: {} u[2]: {} u[3]: {}'.format(hex_str_u0, hex_str_ip_src, hex_str_ip_dest, hex_str_u3))
    logging.debug("crc u0 {:08x}".format(crc1 ^ 0xffffffff))
    logging.debug("crc u1 {:08x}".format(crc2 ^ 0xffffffff))
    logging.debug("crc u2 {:08x}".format(crc3 ^ 0xffffffff))
    logging.debug("crc u3 {:08x}".format(crc4 ^ 0xffffffff))

    # The crc_data encompass all the different u0 through u3 stages.
    crc_calc = crc32c.crc32c(binascii.a2b_hex(crc_data))^0xffffffff
    logging.debug('crc_calc {:08x}'.format(crc_calc))
    crc_mod = crc_calc%mod
    logging.debug('crc_mod {}'.format(crc_mod))
    return(crc_mod)

def old_crc_hash(dest_ip, src_ip, mod):
    ip_dest = socket.inet_aton(str(dest_ip))
    ip_src = socket.inet_aton(str(src_ip))
    ip_dest_big = int.from_bytes(ip_dest, byteorder='big')
    ip_src_big = int.from_bytes(ip_src, byteorder='big')
    dest = ip_dest_big ^ 0xaabbccdd
    hash = (dest >> 12) ^ (dest >> 7) ^ (dest >> 28) ^ (dest << 1)
    hash ^= (ip_src_big >> 9) ^ (ip_src_big >> 11)
    logging.debug("ip_dest {} ip_dest_big {} ip_src {} ip_src_big {} hash {}".format(ip_dest, hex(ip_dest_big), ip_src, hex(ip_src_big), hex(hash)))
    crc_mod = hash%mod
    logging.debug('crc_mod {}'.format(crc_mod))
    return(crc_mod)

def init_unique_hash_list(mod, num_tunnels):
    unique_list = [ ['0']*(mod) for i in range(int(num_tunnels/mod))]
    return(unique_list)

def check_save_unique_hash(unique_hash_list, ip_dest, ip_src, hash, hash_reverse):
    save = 'TRUE'
    last_dst_tuple = str(ip_dest).split('.')[3]
    last_src_tuple = str(ip_src).split('.')[3]
    # debug only
    if hash != hash_reverse:
        return unique_hash_list
    #unique_hash_list_mod = deepcopy(unique_hash_list)
    #print (unique_hash_list_mod)
    for tunnels_list in unique_hash_list:
        #if tunnels_list[hash] == '0' and int(last_dst_tuple) > 3 and int(last_src_tuple) > 3 and last_dst_tuple == last_src_tuple:
        if tunnels_list[hash] == '0' and int(last_dst_tuple) > 3 and int(last_src_tuple) > 3:
            for idx in range (0, len(tunnels_list)):
                unique_ip = tunnels_list[idx].split(' ')
                if len(unique_ip) > 1:
                    # print('unique ip {}'.format(unique_ip[1]))
                    # if unique_hash_list text format changes then the index need to change as well.
                    if unique_ip[0] == str(ip_dest) or unique_ip[1] == str(ip_src):
                        save = 'FALSE'
            if save == 'TRUE':
                #tunnels_list[hash] = '{} {} {}'.format(str(ip_dest), str(ip_src), str(hash))
                tunnels_list[hash] = '{} {}'.format(str(ip_dest), str(ip_src))
                #print ('got a unique {}<===>{}<===>{}'.format(str(ip_dest), str(ip_src), str(hash)))
                #print (unique_hash_list_mod)
                #unique_hash_list = deepcopy(unique_hash_list_mod)
                break
    return unique_hash_list

def generate_ip_addr_pair(dest_network, src_network, prot, src_port, dst_port, mod_value, num_tunnels, old_crc, unique_hash, hash_result_list, hash_dict_list, normalize, matching):
    dest_ip_list = []
    src_ip_list = []
    dest_ip_network_list = []
    src_ip_network_list = []
    unique_hash_list = []
    prot_list = []
    src_port_list = []
    dst_port_list = []

    for dest_ip in ipaddress.IPv4Network(dest_network):
        dest_ip_network_list.append(dest_ip)
        if hash_dict_list["dest_ip"].get(str(dest_ip)) is None:
            hash_dict_list["dest_ip"][str(dest_ip)] = list()
    for src_ip in ipaddress.IPv4Network(src_network):
        src_ip_network_list.append(src_ip)
        if hash_dict_list["src_ip"].get(str(src_ip)) is None:
            hash_dict_list["src_ip"][str(src_ip)] = list()
    for ip_dest, ip_src in itertools.product(dest_ip_network_list, src_ip_network_list):
        if matching != 0:
            if int(ip_dest) & matching != int(ip_src) & matching:
                continue
        dest_ip_list.append(ip_dest)
        src_ip_list.append(ip_src)
        prot_list.append(prot)
        dst_port_list.append(int(dst_port))
        src_port_list.append(int(src_port))
    if old_crc is not None:
        mod_value = 8
        unique_hash_list = init_unique_hash_list(mod_value, num_tunnels)
        for idx in range (0, len(dest_ip_list)):
            ip_dest = dest_ip_list[idx]
            ip_src = src_ip_list[idx]
            hash = old_crc_hash(ip_dest, ip_src, mod_value)
            hash_reverse = old_crc_hash(ip_src, ip_dest, mod_value)
            logging.debug('{:15} {:15} ==> hash {:3d}'.format(str(ip_dest), str(ip_src), hash))
            hash_result_list.append('{:16} {:16} {:5} {:8}'.format(str(ip_dest), str(ip_src), str(hash), str(hash_reverse)))
            check_save_unique_hash(unique_hash_list, ip_dest, ip_src, hash, hash_reverse)

    else:
        unique_hash_list = init_unique_hash_list(mod_value, num_tunnels)
        for idx in range (0, len(dest_ip_list)):
            ip_dest = dest_ip_list[idx]
            ip_src = src_ip_list[idx]
            prot = prot_list[idx]
            src_port = src_port_list[idx]
            dst_port = dst_port_list[idx]
            hash = crc_hash(ip_dest, ip_src, prot, src_port, dst_port, mod_value, normalize)
            hash_reverse = crc_hash(ip_src, ip_dest, prot, src_port, dst_port, mod_value, normalize)
            logging.debug('{:15} {:15} ==> hash {:3d}'.format(str(ip_dest), str(ip_src), hash))
            hash_result_list.append('{:16} {:16} {:5} {:8} {:11} ==>    {:8} {:8}'.format(str(ip_dest), str(ip_src), str(prot), str(dst_port), str(src_port), str(hash), str(hash_reverse)))
            hash_dict_list["dest_ip"][str(ip_dest)].append('{:16} {:16} {:5} {:8} {:11} ==>    {:8} {:8}'.format(str(ip_dest), str(ip_src), str(prot), str(dst_port), str(src_port), str(hash), str(hash_reverse)))
            hash_dict_list["src_ip"][str(ip_src)].append('{:16} {:16} {:5} {:8} {:11} ==>    {:8} {:8}'.format(str(ip_dest), str(ip_src), str(prot), str(dst_port), str(src_port), str(hash), str(hash_reverse)))
            hash_dict_list["hash"][hash].append('{:16} {:16} {:5} {:8} {:11} ==>    {:8} {:8}'.format(str(ip_dest), str(ip_src), str(prot), str(dst_port), str(src_port), str(hash), str(hash_reverse)))
            unique_hash_list = check_save_unique_hash(unique_hash_list, ip_dest, ip_src, hash, hash_reverse)

    #print('{:16} {:16} {:5} {:8} {:16} {:5} {:8}'.format('Dest:', 'Src:', 'Prot', 'dstport', 'srcport', 'Hash:', 'Rev-hash:'))
    #for index in range(0, len(hash_result_list)):
    #    print(hash_result_list[index])
    if unique_hash is not None:
        print("\nUnique hash:")
        for count, index in enumerate(unique_hash_list):
            #print(f"------ Tunnels set {count} ---------")
            for value in index:
                print("{} {} {} {}".format(value, prot, dst_port, src_port))

def sort_values(result_sort_hash_dict_list, mod_value):
    #print("sort values\n")
    #pretty = json.dumps(result_sort_hash_dict_list, indent=4, sort_keys=True)
    #print(pretty)
    prev_queue_utilization = 0
    for keys, values in result_sort_hash_dict_list.items():
        hash_dict = {}
        rev_hash_dict = {}
        unused_queue_list = []
        used_queue_list = []
        unused_queue = 0
        unused_rev_queue_list = []
        used_rev_queue_list = []
        unused_rev_queue = 0

        for index in range (0, mod_value):
            hash_dict[str(index)] = 0
            rev_hash_dict[str(index)] = 0
        for data in values:
            search = re.search("^.*==>\s*(.\d*)\s*(.\d*).*", data)
            hash = search.group(1)
            rev_hash = search.group(2)
            hash_dict[hash] = hash_dict[hash] + 1
            rev_hash_dict[rev_hash] = rev_hash_dict[rev_hash] + 1
        for qnum, num in hash_dict.items():
            if num == 0:
                unused_queue = unused_queue + 1
                unused_queue_list.append(qnum)
            else:
                used_queue_list.append(qnum)

        for qnum, num in rev_hash_dict.items():
            if num == 0:
                unused_rev_queue = unused_rev_queue + 1
                unused_rev_queue_list.append(qnum)
            else:
                used_rev_queue_list.append(qnum)

        queue_utilization = mod_value - unused_queue
        rev_queue_utilization = mod_value - unused_rev_queue
        for k,v in hash_dict.items():
            result_sort_hash_dict_list[keys].append(f'hash: {k} : {v}')
        #result_sort_hash_dict_list[keys].append((": ".join("TxQ {} Usage {}".format(k,v) for k,v in txq_dict.items())))
        result_sort_hash_dict_list[keys].append("Unused queue : {}".format(unused_queue))
        result_sort_hash_dict_list[keys].append("Unused queue list : {}".format(unused_queue_list))
        result_sort_hash_dict_list[keys].append("Queue utilizations : {}".format(queue_utilization))
        result_sort_hash_dict_list[keys].append("Queue utilizations list : {}".format(used_queue_list))
        for k,v in rev_hash_dict.items():
            result_sort_hash_dict_list[keys].append(f'rev hash: {k} : {v}')
        result_sort_hash_dict_list[keys].append("Rev Unused queue : {}".format(unused_rev_queue))
        result_sort_hash_dict_list[keys].append("Rev Unused queue list : {}".format(unused_rev_queue_list))
        result_sort_hash_dict_list[keys].append("Rev Queue utilizations : {}".format(rev_queue_utilization))
        result_sort_hash_dict_list[keys].append("Rev Queue utilizations list : {}".format(used_rev_queue_list))
        if queue_utilization > prev_queue_utilization:
            prev_queue_utilization = queue_utilization
            queue_utilization_dict = {}
            queue_utilization_dict[keys] = deepcopy(result_sort_hash_dict_list[keys])
        elif prev_queue_utilization == queue_utilization:
            queue_utilization_dict[keys] = deepcopy(result_sort_hash_dict_list[keys])
    pretty = json.dumps(result_sort_hash_dict_list, indent=4)
    print(pretty)
    #print("\n**** Max Queue Utilization ************\n")
    #pretty = json.dumps(queue_utilization_dict, indent=4)
    #print(pretty)


def parse_sort_values(sort_value, sort_hash_dict_list, result_sort_hash_dict_list, mod_value):
    #result_sort_hash_dict_list = {}
    if sort_value is not None:
        if sort_value == "ALL" or sort_value == "all":
            pretty = json.dumps(sort_hash_dict_list, indent=4, sort_keys=True)
            result_sort_hash_dict_list = deepcopy(sort_hash_dict_list)
        else:
            pretty = json.dumps(sort_hash_dict_list[sort_value], indent=4, sort_keys=True)
            result_sort_hash_dict_list[sort_value] = deepcopy(sort_hash_dict_list[sort_value])
        sort_values(result_sort_hash_dict_list, mod_value)
        #print(pretty)

def ip_addr_sort(sort_src_value, sort_dest_value, sort_hash, hash_result_list, hash_dict_list, result_sort_hash_dict_list, mod_value):
    if sort_src_value is not None:
        parse_sort_values(sort_src_value, hash_dict_list["src_ip"], result_sort_hash_dict_list, mod_value)
    if sort_dest_value is not None:
        parse_sort_values(sort_dest_value, hash_dict_list["dest_ip"], result_sort_hash_dict_list, mod_value)
    if sort_hash is not None:
        parse_sort_values(sort_hash, hash_dict_list["hash"], result_sort_hash_dict_list, mod_value)

def print_distribution(mod_value, distrib_num, distrib_start, hash_result_list):
    start_print = "FALSE"
    distribution1 = [0 for _ in range(mod_value)]
    distribution2 = [0 for _ in range(mod_value)]
    for num_hash, hash_result in enumerate(hash_result_list):
        search = re.search("^\s*(\d*.\d*.\d*.\d*)\s*(\d*.\d*.\d*.\d*).*==>\s*(.\d*)\s*(.\d*).*", hash_result)
        if ((search.group(1) == distrib_start) or (search.group(2) == distrib_start)) :
            start_print = "TRUE"
            print_index = 1
        if start_print == "TRUE":
            distribution1[int(search.group(3))] += 1
            distribution2[int(search.group(4))] += 1
            print (hash_result)
            if print_index < distrib_num:
                print_index += 1
            else:
                break
    num_hash = print_index
    print ("----------------------------------------------------------")
    print (f"Hash Distribution: {num_hash} entries")
    print ("Hash value:     #hash       %hash     #rev-hash    %rev-hash")
    for index in range(0, len(distribution1)):
        print (f"{index:>10} {distribution1[index]:>10}  {distribution1[index]/num_hash * 100 :>10.2f} {distribution2[index]:>10} {distribution2[index]/num_hash * 100 :>10.2f} ")


def main(argv):
    hash_result_list = []
    hash_dict_list = {}
    result_sort_hash_dict_list = {}
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip_file", help = "file name with ip pair: ex. <dst> <src> <prot> <port> <port>")
    parser.add_argument("--old_crc", help = 'Set as 1 to enable crc based on 17.8 and earlier release. ')
    #parser.add_argument("--mod_value", help = 'hash module')
    parser.add_argument("--dest_network", help = 'destination ip address ex. 192.168.1.0/24')
    parser.add_argument("--src_network", help = 'source ip address ex. 192.168.2.0/24')
    parser.add_argument("--unique_hash", help = 'set to 1 to find unique hash index.')
    parser.add_argument("--prot", help = 'specify protocol as gre, tcp, udp or any decimal number')
    parser.add_argument("--src_port", help = 'source port associate with protocol')
    parser.add_argument("--dst_port", help = 'destination port associate with protocol')
    parser.add_argument("--num_tunnels", help = 'number of ipsec tunnels: default=12')
    parser.add_argument("--modulo", help = 'hash modulo: default = 12')
    parser.add_argument("--sort_src", help= 'sort based on src address --sort_src 10.3.2.1')
    parser.add_argument("--sort_dest", help='sort based on dest address --sort_dest 10.5.4.32')
    parser.add_argument("--sort_hash", help='sort based on txq --sort_hash 10: default = all' )
    parser.add_argument("--normalize", help='normalize the src and dst: default = TRUE' )
    parser.add_argument("--matching", help='How many bits to compare the src and dest to match addresses: default = 8 Ex: the last 8 bits match between src and dst 1.0.0.34 2.0.0.34' )
    parser.add_argument("--distrib", help='calculate hash distribution given starting address and number of entries, use in conjunction with --matchiing ex: --distrib 10.3.2.15,250' )
    args = parser.parse_args()
    if args.distrib is not None:
        distrib_args = args.distrib
        distrib_start, distrib_num = distrib_args.split(",")
        distrib_start = distrib_start.strip()
        distrib_num = int(distrib_num.strip())
    else:
        distrib_start = 0
        distrib_num = 0

    if args.matching is not None and int(args.matching) > 0:
        matching = int(args.matching)
        matching = (1 << int(args.matching)) - 1
    else:
        matching = 0

    if args.modulo is not None:
        mod_value = int(args.modulo)
        #for i in range (0,mod_value):
        #    unique_hash_list.append('0')
    else:
        mod_value = 12

    if args.num_tunnels is not None:
        num_tunnels = int(args.num_tunnels)
        #for i in range (0,mod_value):
        #    unique_hash_list.append('0')
    else:
        num_tunnels = 12

    if (num_tunnels % mod_value) != 0:
        print(f"The num_tunnels parameter {num_tunnels} must be divisible by modulo {mod_value}.")
        exit(1)

    prot = 0
    if args.prot is not None:
        if args.prot == 'gre':
            prot = 47
        elif args.prot == 'tcp':
            prot = 6
        elif args.prot == 'udp':
            prot = 17
        elif args.prot.isdigit():
            prot = int(args.prot)
    if args.dest_network is not None:
        dest_network = args.dest_network
    else:
        dest_network = '192.168.1.0/24'
    if args.src_network is not None:
        src_network = args.src_network
    else:
        src_network = '192.168.2.0/24'
   
    if args.src_port is not None:
        src_port = args.src_port
    else:
        src_port = 0
    if args.dst_port is not None:
        dst_port = args.dst_port
    else:
        dst_port = 0

    sort_src_value = args.sort_src

    sort_dest_value = args.sort_dest

    if args.sort_hash is not None:
        sort_hash = args.sort_hash
        if sort_hash.isdigit():
            sort_hash = int(sort_hash)
        else:
            sort_hash = sort_hash.upper()
    else:
        sort_hash = args.sort_hash

    if args.normalize is None:
        normalize = "TRUE"
    else:
        normalize = args.normalize.upper()

    #uncomment the line below to output debug messages
    #logging.basicConfig(level=logging.DEBUG)
    hash_dict_list["dest_ip"] = {}
    hash_dict_list["src_ip"] = {}
    hash_dict_list["hash"] = {}
    for mod in range (0, mod_value):
        hash_dict_list["hash"][mod] = list()

    if args.ip_file is not None:
        with open(args.ip_file) as f:
            for line in f:
                if len(line) < 5:
                    continue
                data = line.split(' ')
                #print("data {}".format(data))
                dst = data[0]
                #src = data[1].split('\n')[0]
                src = data[1]
                prot = int(data[2])
                dst_port = int(data[3])
                src_port = int(data[4].split('\n')[0])
                #src = data[1]
                args.unique_hash = None
                generate_ip_addr_pair(dst, src, prot, src_port, dst_port, mod_value, num_tunnels, args.old_crc, args.unique_hash, hash_result_list, hash_dict_list, normalize, matching)
    else:
        generate_ip_addr_pair(dest_network, src_network, prot, src_port, dst_port, mod_value, num_tunnels, args.old_crc, args.unique_hash, hash_result_list, hash_dict_list, normalize, matching)

    print('{:16} {:16} {:5} {:8} {:16} {:5} {:8}'.format('Dest:', 'Src:', 'Prot', 'dstport', 'srcport', 'Hash:', 'Rev-hash:'))
    if distrib_num != 0:
        print_distribution(mod_value, distrib_num, distrib_start, hash_result_list)
    else:
        for num_hash, hash_result in enumerate(hash_result_list):
            print (hash_result)
    #pretty = json.dumps(hash_dict_list, indent=4, sort_keys=True)
    #print(pretty)
    ip_addr_sort(sort_src_value, sort_dest_value, sort_hash, hash_result_list, hash_dict_list, result_sort_hash_dict_list, mod_value)

if __name__ == "__main__":
    main(sys.argv[1:])

