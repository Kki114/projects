#!/usr/bin/python

from scapy.all import Ether, IP, ICMP, sr1

data = b'Hello Router'

pkt = IP(src="192.168.10.106", dst="192.168.10.1")/ICMP()/data

resp = sr1(pkt)

resp.show()