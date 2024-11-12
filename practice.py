from scapy.all import srp, srp1, sr1, Ether, ARP, IP, UDP, ICMP, hexdump
import sys
from typing import Optional


def get_mac(targetip: str) -> Optional[str]:
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=targetip)  # type = scapy.layers.l2.Ether
    print(type(packet))
    ans, _ = srp(packet, timeout=2, retry=10, verbose=False)

    for _, a in ans:
        #print(type(a[Ether].src))
        return a[Ether].src # Return source MAC address
    return None # If no response, return 'None'


if __name__ == '__main__':
    try:
        if sys.argv[1]:
            ip = sys.argv[1]
            mac = get_mac(ip)
        print(mac)
    except IndexError:
        sys.stderr.write("Error: Not enough information from user.")
        sys.stderr.write("Format: sudo python <ip>")
'''
payload = b"HELP!"
pkt = Ether(dst='54:05:db:f9:5d:62')/IP(dst='192.168.128.50')/ICMP()/payload
#pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(psrc='0.0.0.0', pdst='192.168.128.50')   # Find next hop using ARP on a network
#pkt = Ether(dst='a8:46:9d:fe:c1:21')/IP(dst='192.168.128.1')/ICMP()/payload   # Send a ping to a certain MAC & IP 
pkt.show()
hexdump(pkt)
send = sr1(pkt)


if send:
    send.show()
    hexdump(send)
'''
