from scapy.all import *

packets = rdpcap("h3dump.pcap")

for p in packets:
    if p.haslayer(TCP):
        print("Packet from %s to %s" % (p[IP].src, p[IP].dst))
        print("Sequence number %s, ack number %s" % (p[TCP].seq, p[TCP].ack))
    # print(p.show())
