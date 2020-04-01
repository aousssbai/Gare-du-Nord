class PACKET: 
    def __init__(self, source_ip = '0.0.0.0', dest_ip = '0.0.0.0', seq_num = 0, ack_num = 0, flag = '', data = '', tag = ''):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flag = flag
        self.data = data
        self.tag = tag


class HOST:
    def __init__(self, ip_address = '0.0.0.0', name = '', seq_counter = 0, ack_counter = 0, handshake_complete = False, size_last_payload = 0):
        self.ip_address = ip_address
        self.name = name
        self.seq_counter = seq_counter
        self.ack_counter = ack_counter
        self.handshake_complete = handshake_complete
        self.size_last_payload = size_last_payload

    def receive(self, packet):
        # Call a function for each different possible flag
        if packet.flag == 'S':
            return self.syn(packet)
        if packet.flag == 'SA':
            return self.synack(packet)
        if packet.flag == 'A':
            return self.ack(packet)
        if packet.flag == 'R':
            return self.reset(packet)
        
        # If there is no flag match, do nothing
        return None

    def syn(self, received_packet):

        if received_packet.ack_num == 0 and not self.handshake_complete:
            # Reply with a SYN-ACK packet
            self.ack_counter = received_packet.seq_num + 1
            p = PACKET(self.ip_address, received_packet.source_ip, self.seq_counter, self.ack_counter, 'SA', '')
            return p
        else:
            # Drop packet, i.e. do nothing
            return None

    def synack(self, received_packet):

        if received_packet.ack_num == self.seq_counter + 1:
            # Reply with an ACK packet, finalising the tcp handshake
            self.seq_counter = received_packet.ack_num
            self.ack_counter = received_packet.seq_num + 1 
            self.handshake_complete = True
            p = PACKET(self.ip_address, received_packet.source_ip, self.seq_counter, self.ack_counter, 'A', '')
            return p
        else: 
            #Drop packet
            return None

    def ack(self, received_packet):

        # Final stage in 3 way handshake
        if not self.handshake_complete: 
            if received_packet.seq_num == self.ack_counter and received_packet.ack_num == self.seq_counter + 1:
                 # Update value of sequence number, finalising tcp handshake
                self.seq_counter = received_packet.ack_num
                self.handshake_complete = True
            return None

        # If handshake has already happened
        else:
            # Receives data from another host
            if received_packet.seq_num == self.ack_counter + 1 and received_packet.ack_num == self.seq_counter:
                self.ack_counter = received_packet.seq_num + len(received_packet.data)
                p = PACKET(self.ip_address, received_packet.source_ip, self.seq_counter, self.ack_counter, 'A', '')
                return p
            # Receives response from sending data to a host
            elif received_packet.seq_num == self.ack_counter and received_packet.ack_num == self.seq_counter + self.size_last_payload:
                # Update value of sequence number
                self.seq_counter = received_packet.ack_num
            return None

    def reset(self, received_packet):
        if self.name == 'h1':
            self.seq_counter = 3000
        else: 
            self.seq_counter = 4000
        self.ack_counter = 0

    def craft_syn_packet(self, dest_ip):
        p = PACKET(self.ip_address, dest_ip, self.seq_counter, self.ack_counter, 'S', '')
        return p
    
    def craft_data_packet(self, dest_ip, data):
        self.seq_counter = self.seq_counter + 1
        self.size_last_payload = len(data)
        p = PACKET(self.ip_address, dest_ip, self.seq_counter, self.ack_counter, 'A', data)
        return p


class ATTACKER:
    def __init__(   self, name = '', h1_seq_counter = 0, h1_ack_counter = 0, h2_seq_counter = 0,
                    h2_ack_counter = 0, h1_handshake_complete = False, h2_handshake_complete = False):
        self.name = name
        self.h1_seq_counter = h1_seq_counter
        self.h1_ack_counter = h1_ack_counter
        self.h2_seq_counter = h2_seq_counter
        self.h2_ack_counter = h2_ack_counter
        self.h1_handshake_complete = h1_handshake_complete
        self.h2_handshake_complete = h2_handshake_complete

    def intercept(self, packet):
        # Call a function for each different possible flag
        if packet.flag == 'S':
            return self.syn(packet)
        if packet.flag == 'SA':
            return self.synack(packet)

        # If there is no flag match, do nothing         
        return None

    def syn(self, intercepted_packet):
        # Assuming packet comes from h1
        self.h1_seq_counter = intercepted_packet.seq_num
        self.h1_ack_counter = intercepted_packet.ack_num
        return None

    def synack(self, intercepted_packet):
        # Assuming packet comes from h2
        # It comes either after the real SYN from h1 or after the crafted SYN by the attacker
        if intercepted_packet.ack_num != 5001:                                                          # 5000 = sequence number in the crafted SYN
            self.h1_seq_counter = intercepted_packet.ack_num
            self.h1_ack_counter = intercepted_packet.seq_num + 1
            self.h1_handshake_complete = True

            packet_list = []
            reset_packet = PACKET('1.1.1.1', '2.2.2.2', intercepted_packet.ack_num, 0, 'R', '', 'h3')       # Fake RST packet from h1
            syn_packet = PACKET('1.1.1.1', '2.2.2.2', 5000, 0, 'S', '', 'h3')                               # Fake SYN packet from h1
            packet_list.append(reset_packet)        
            packet_list.append(syn_packet)
            return packet_list
        else:
            self.h2_seq_counter = intercepted_packet.seq_num + 1
            self.h2_ack_counter = intercepted_packet.ack_num
            self.h1_handshake_complete = True
            p = PACKET('1.1.1.1', '2.2.2.2', 5001, self.h2_seq_counter, 'A', '', 'h3')
            packet_list = []
            packet_list.append(p)
            return packet_list


class TCP: 
    def __init__(self, attacker_active = False):
        self.host_1 = HOST('1.1.1.1', 'h1', 1000, 0, False)
        self.host_2 = HOST('2.2.2.2', 'h2', 2000, 0, False)
        self.host_3 = ATTACKER('h3', 0, 0, 0, 0)
        self.ip_list = {'h1': '1.1.1.1', 'h2': '2.2.2.2'}
        self.packet_list = []
        self.processed_packet_list = []
        self.attacker_active = attacker_active

    def send_packet(self, packet):
        if self.attacker_active and packet.tag != 'h3':
            crafted_packets = self.host_3.intercept(packet)
            if crafted_packets is not None:
                for crafted_packet in crafted_packets:         
                    self.packet_list.append(crafted_packet)

        if packet.dest_ip == self.ip_list['h1']: 
            # Packet is for host 1
            # If host 1 sends a packet back, it is contained in the response_packet variable
            response_packet = self.host_1.receive(packet)
            self.processed_packet_list.append(packet)
            if response_packet is not None:
                self.packet_list.append(response_packet)

        if packet.dest_ip == self.ip_list['h2']:
            # Packet is for host 2 
            # If host 2 sends a packet back, it is contained in the response_packet variable
            response_packet = self.host_2.receive(packet)
            self.processed_packet_list.append(packet)
            if response_packet is not None:
                self.packet_list.append(response_packet)

    
    def process_other_packets(self):
        while(len(self.packet_list) != 0):
            packet = self.packet_list.pop(0)
            self.send_packet(packet)

    def print_all_packets(self):
        # Show all the packets that have been processed
        for a in self.processed_packet_list:
            print(a.__dict__)
        # return self.processed_packet_list               # Change when done debugging!
    


if __name__ == '__main__':

    tcp = TCP()                                                     # First TCP object, without an attacker

    syn_packet = tcp.host_1.craft_syn_packet('2.2.2.2')             # SYN packet from h1 to h2
    
    tcp.send_packet(syn_packet)                                     # Send this packet
    tcp.process_other_packets()                                     # Manage all others that are generated as a result
    print('Packets in TCP handshake without attacker:')
    tcp.print_all_packets()                                         # Print all packets that were sent in the network

    print('After TCP handshake:')
    print('Host 1 seq num = {}, ack num = {}'.format(tcp.host_1.seq_counter, tcp.host_1.ack_counter))
    print('Host 2 seq num = {}, ack num = {}'.format(tcp.host_2.seq_counter, tcp.host_2.ack_counter))
    
    data = '10letters0'                                             # Payload, a string with 10 characters
    data_packet = tcp.host_1.craft_data_packet('2.2.2.2', data)     # Packet from h1 to h2 with some data
    tcp.send_packet(data_packet)
    tcp.process_other_packets()
    print('After data exchange with payload of size 10:')
    print('Host 1 seq num = {}, ack num = {}'.format(tcp.host_1.seq_counter, tcp.host_1.ack_counter))
    print('Host 2 seq num = {}, ack num = {}'.format(tcp.host_2.seq_counter, tcp.host_2.ack_counter))

    print('=======================================================================================================================================')
    print('Packets in TCP handshake with attacker:')

    tcp_2 = TCP(True)                                               # Second TCP object, with an attacker
    syn_packet = tcp_2.host_1.craft_syn_packet('2.2.2.2')           # SYN packet from h1 to h2
    
    tcp_2.send_packet(syn_packet)                                   # Send this packet
    tcp_2.process_other_packets()                                   # Manage all others that are generated as a result
    tcp_2.print_all_packets()                                       # Print all packets that were sent in the network
    print('After TCP handshake:')
    print('Host 1 seq num = {}, ack num = {}'.format(tcp_2.host_1.seq_counter, tcp_2.host_1.ack_counter))
    print('Host 2 seq num = {}, ack num = {}'.format(tcp_2.host_2.seq_counter, tcp_2.host_2.ack_counter))
    print('The sequence and ack numbers are not syncronised for both hosts, even though they both think they have completed the handshake')
    print('This means they are not able to exchange any data unless the attacker adapts the packets they send to each other to have the correct values')

