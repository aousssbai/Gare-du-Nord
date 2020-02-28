import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('127.0.0.1', 10000)
print('connecting to ' + server_address[0] + ' port 10000', )
sock.connect(server_address)


try:
    
    # Send data
    message = b'sample message'
    # print('sending ' + message)
    sock.sendall(message)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)
    
    while amount_received < amount_expected:
        data = sock.recv(16)
        amount_received += len(data)
        print('received ' + data)

finally:
    print('closing socket')
    sock.close()