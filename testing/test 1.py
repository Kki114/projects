#!/usr/bin/python

from scapy.all import sr1, Ether, IP, ICMP, ARP
import time

x = time.time()
pkt = ARP(op="who-has", pdst="192.168.128.1", hwdst="ff:ff:ff:ff:ff:ff")
#pkt.show()
broadcast = pkt[ARP].hwdst
send = sr1(pkt)
router_mac = send[ARP].hwsrc
router_ip = send[ARP].psrc
print(f"Program took {time.time() - x} seconds to get response for ARP message.")

ping_pkt = Ether(dst=router_mac)/IP(dst=router_ip)/ICMP()/b"Message Confirmation"
ping_pkt.show()
send1 = sr1(ping_pkt)
if send1 is not None:
    send1.show()
