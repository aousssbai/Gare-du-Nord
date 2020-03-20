import socket
import sys
from scapy.all import *

# # Create a TCP/IP socket
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# # Connect the socket to the port where the server is listening
# server_address = ('127.0.0.1', 10000)
# print('connecting to ' + server_address[0] + ' port' + str(server_address[1]))
# sock.connect(server_address)


# try:
    
#     # Send data
#     # message = b'sample message'
#     # print('sending ' + str(message))
#     p = IP(dst="127.0.0.1")/TCP(flags="S", sport=RandShort(),dport=10000)/Raw("Hallo world!")
#     sock.send(bytes(p))
#     # sock.sendall(message)

#     # Look for the response
#     amount_received = 0
#     amount_expected = len(p)
    
#     while amount_received < amount_expected:
#         data = sock.recv(16)
#         amount_received += len(data)
#         print('received ' + str(data))

# finally:
#     print('closing socket')
#     sock.close()
# s=socket.socket()
# s.connect(("127.0.0.1",10000))
# ss=StreamSocket(s,Raw)
# p = IP(dst="127.0.0.1")/TCP(flags="S", sport=RandShort(),dport=10000)/Raw("Hallo world!")
# ss.sr1(Raw(p))
from scapy.all import *

sport = random.randint(1024,65535)

# SYN
ip=IP(src="127.0.0.1",dst="127.0.0.1")
SYN=TCP(sport=sport,dport=255,flags='S',seq=1000)
SYNACK=sr1(ip/SYN)

# SYN-ACK
ACK=TCP(sport=sport, dport=255, flags='A', seq=SYNACK.ack + 1, ack=SYNACK.seq + 1)
send(ip/ACK)

