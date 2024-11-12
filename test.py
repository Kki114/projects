from scapy.all import send, sniff, Ether, IP, UDP
import sys
import threading
import time


class Payload:
    def __init__(self):

        self.eth = Ether(src='01:02:03:04:05:06')
        self.ip = IP(dst='192.168.128.0')
        self.udp = UDP(dport= 9998)
        #self.ping = ICMP()
        self.msg = b"PYTHONRULES!"
        self.payload = self.ip/self.udp/self.msg   # type <class 'scapy.layer.inet.IP'>
        self.payload.show()

        # Try statement to get user input for num of packets to sniff
        try:
            while True:
                self.num_count = input("How many packets to sniff for?: ")
                self.num_count = int(self.num_count)
                if self.num_count:
                    print(type(self.num_count))
                    print(f"Sniffing for {self.num_count} packets...")
                    break
                else:
                    print(f"Please enter a valid number.\n")
        except TypeError as e:
            print(e)
        except KeyboardInterrupt:
            print("User Interrupt\n")
                    #udp_spam(self.payload)
                    #self.payload.show()

    
    def sniffer(packet):
        '''
        if packet[UDP].payload:
            mypacket = str(packet[UDP].payload)
        '''
        try:
            packet.show()
        except KeyboardInterrupt:
            sys.exit()

        #sys.exit()


def udp_spam(payload, N_count: int) -> None:
    count: int = N_count
    try:
        while True:
            send = send(payload, count=count)
    except KeyboardInterrupt:
        print('\nUser Interrupt\n')
        sys.exit()



            
            

#print(p)    # Prints 'IP / TCP 127.0.0.1:ftp_data > 127.0.0.1:http S / Raw'
#print(f'{p}')   # Prints the same as above
#print(f'{p[TCP]}')  # Prints only the TCP layer of created packet 'p'

# Change the 'src' field of the Ethernet frame
#p += p[Ether(src='01:02:03:04:05:06')]
#ping.show()

if __name__ == '__main__':
    

    p = Payload()   
    spam = threading.Thread(target=udp_spam, args=(p.payload, p.num_count))

    print('##### Beginning message spam #####')
    time.sleep(3)

    spam.start()
    sniff(filter='dst 192.168.129.204', iface='any', prn=p.sniffer, count=p.num_count)

    