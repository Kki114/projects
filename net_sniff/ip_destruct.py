import ipaddress
import struct
import sys

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
        #print(self.dst_address)

        # Map protocol constants to their name
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

class ICMP:

    def __init__(self, buff=None):
        icmp_header = struct.unpack('<BBHHH', buff)

        self.type = icmp_header[0]
        self.code = icmp_header[1]
        self.sum = icmp_header[2]
        self.id = icmp_header[3]
        self.seq = icmp_header[4]



#thing1 = bytes.fromhex('AA')
#print(sys.stdout.buffer.write('x\11'))

x = struct.pack('<5s', b'Hello')
print(f'{x} :{len(x)} :{sys.stdout.buffer.write(x)}')
y = struct.unpack('<5s', x[0:])
print(f'{y} :{len(y)} :{sys.stdout.buffer.write(y[0])}')

thing = (b'E\x00\x00T\xf1\\\x00\x008\x01\x9c\xba\x8e\xfb\xa3\x8a\xc0\xa8\x01d\x00\x00\xccM\x07p\x00\x01.\x7f\xf1c\x00\x00\x00\x00G\x8b\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567')

#print(len(thing))
destroy = IP(thing[0:20])
offset = destroy.ihl * 4
icmp = ICMP(thing[offset:offset + 8])
print(f"{icmp.type} :0 means 'Echo Reply'")
print(f"{icmp.code} :0 means 'Echo Reply'")
print(f"{icmp.sum} :Header Checksum value ({icmp.sum / 8})")
print(f"{icmp.id} :")
print(f"{icmp.seq} :")
'''
print(f'Version Value: {destroy.ver}')
print(f'Internet Header Length: {destroy.ihl} * 4-byte blocks = {destroy.ihl * 4} bytes long.')  # ihl is how many "words" or 32-byte blocks there are
print(f'Type of Service: {destroy.tos}')
print(f'Total Length: {destroy.len // 4}')
print(f'Time to Live: {destroy.ttl}')
print(f'Protocol # {destroy.protocol_num}')
print(f'Source IP (raw): {destroy.src}')
print(f'Source IP: {destroy.src_address}')
print(f'Destination IP (raw): {destroy.dst}')
print(f'Source IP: {destroy.dst_address}')
print(f'src: {destroy.src_address} --> dst: {destroy.dst_address}')
'''