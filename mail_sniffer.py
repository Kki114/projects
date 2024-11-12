from scapy.all import *
import threading

def packet_callback(packet):
    print(packet.show())

if __name__ == '__main__':

    sniff(prn=packet_callback, count=1)