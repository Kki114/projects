#!/usr/bin/python

"""
Created by Khari Walker

Date of creation: 11/4/2024

Description:
It's largely just a fun project that I plan to flesh out into a 
semi-independent program that asks the user questions about what packets
they intend to send.
"""

from scapy.all import Ether, ARP, IP, ICMP, sr1

data = b'Hello Router'

pkt = IP(src="192.168.10.106", dst="192.168.10.1")/ICMP()/data

pkt.show()

resp = sr1(pkt)

resp.show()