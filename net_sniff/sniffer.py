#import argparse
import ipaddress
import os
import socket
import struct
import sys
import threading
import time
#import textwrap

# sniffer source
# Added in 'ip_destruct.py' class to deconstruct the byte stream with struct module
# Added udp_sender() method to send a UDP datagram with 'MESSAGE' 
"""
Description: 

    Sends UDP ping packets to all clients of a specified subnet.
    Returns how many responses were received and tells how many clients are "up".

Potential Project
    
Make a version of the sniffer to scan for TCP packets or UDP datagrams
transferred across the network.  We'll see how difficult it will be.
"""

# Subnet under attack
SUBNET = '192.168.128.0/23'
# Magic string we'll check ICMP responses for
MESSAGE = b"PYTHONRULES!"


# Class to deconstruct IP headers
class IP:

    def __init__(self, buff=None):
        
        header = struct.unpack('<BBHHHBBH4s4s', buff)

        self.ver = header[0] >> 4  # Shifts bits over 4 to save first 4 bits; 10101101 => 00001010
        self.ihl = header[0] & 0xF # Bit-wise '&' operator with 0xF (00001111) or 15 in decimal to preserve the last 4 bits;
                                    # 10101101 AND 00001111 => 00001101
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Human readable IP address
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)
        #print(self.src_address)
        #print(type(self.dst_address))  # Returns <class 'ipaddress.IPv4Address'>
        #print(type(self.src_address))  # Returns <class 'ipaddress.IPv4Address'>

        # Map protocol constants to their name
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No Protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)
    
# Class to deconcstruct ICMP headers
class ICMP:

    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)

        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

# Sprays out the UDP datagrams with our magic message
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(MESSAGE, ((str(ip), 65212)))

# Scans network for ICMP response based on set parameters and outputs information to user
class Scanner:
    def __init__(self, host):
        self.host = host

        # Check if local machine is Windows
        # os.name returns 'nt' when run on Windows machines
        if os.name == 'nt':  
            socket_protocol: int = socket.IPPROTO_IP
            #print("OS is Windows.\n")
        else:
            socket_protocol: int = socket.IPPROTO_ICMP
            #print("OS is not Windows.\n")
        
        # Socket obj to sniff for pings 
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host,0))

        # Include the IP header in the capture
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Turn on promiscuous mode
        if os.name == 'nt':

            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


    def sniff(self):

        hosts_up = set([f'{str(self.host)} *'])

        try:
            # Loop to receive packets
            while True:

                # Receive one packet and print to user
                # Maybe try to store to a list?
                # Maybe print to a folder on the computer?
                #print(f"Packet: {sniffer.recv(65565)}")

                # Receive one packet
                raw_buffer = self.socket.recvfrom(65565)[0]

                # Create an IP header fromt the first 20 bytes
                ip_header = IP(raw_buffer[0:20])

                # If it's ICMP, we want it
                if ip_header.protocol == 'ICMP':

                    # Print the detected protocol and the host
                    #print("Protocol: %s %s --> %s" %
                    #(   ip_header.protocol,
                    #    ip_header.src_address,
                    #    ip_header.dst_address
                    #))
                    #print(f"Version: {ip_header.ver}")
                    #print(f"Header Length: {ip_header.len} TTL: {ip_header.ttl}")

                    # Calculate offset of where ICMP header starts
                    offset = ip_header.ihl * 4

                    # Send ICMP packet to deconstruction class 'ICMP'
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)

                    # Check for TYPE 3 (Host unreachable) and CODE 3 (Destination port unreachable)
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            
                            # Make sure it has our magic message
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == MESSAGE:
                                #print(len(MESSAGE))
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')
                        
        # Catch user interrupt and exit
        except KeyboardInterrupt:

            if os.name == 'nt':
                # Turn off promiscuous mode
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

            print('\nUser Interrupted')
            if hosts_up:
                print(f'\n\nSummary: {len(hosts_up) - 1} hosts up on subnet {SUBNET}\n')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit()
            # Optional: Have user press enter to exit or goodbye message
            #input('Press enter key to exit...')


if __name__ == '__main__':

    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.254.137'
    
    # Create object of Scanner class
    s = Scanner(host)
    time.sleep(5)

    print(f"{'Beginning scan':#^{14+6}}")

    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()

    """
    # Automatically get the host IP
    #HOST = str(socket.gethostbyname(socket.gethostname()))
    # Host to listen on
    if os.name != 'nt':
        HOST = '192.168.129.204'
    elif os.name == 'nt':
        HOST = str(socket.gethostbyname(socket.gethostname()))
    
    parser = argparse.ArgumentParser(
        description='Network Sniffer',
        epilog=textwrap.dedent('''Example:
            sniffer.py -t <localhost>   # Listen on local pc
            ''')
    )
    parser.add_argument('-t', '--target', default=(HOST), help='Specify target to listen on.')
    args = parser.parse_args()
    """
    