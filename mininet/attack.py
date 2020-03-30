from scapy.all import *
import logging

logging.basicConfig(format='%(levelname)s: %(message)s', filename='scapy.log',level=logging.DEBUG)

def isNotOutgoing(pkt):
    return pkt[Ether].src != "00:00:00:00:00:03"

def pkt_callback(pkt):
    print(pkt.show())
    logging.info(pkt.show())

sniff(iface="h3-eth0", prn=pkt_callback, store=0, lfilter=isNotOutgoing)
