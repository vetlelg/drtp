from socket import *
from datetime import datetime
from collections import deque

CHUNK_SIZE = 994
HEADER_SIZE = 6
TIMEOUT = 0.5

class Protocol():
    def __init__(self, server_addr):
        self.seq = 0
        self.ack = 0
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.server_addr = server_addr
    

    def create_packet(self, seq, ack, flags, chunk = b''):
        return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + chunk

    def extract_header(self, packet):
        seq = int.from_bytes(packet[:2], 'big')
        ack = int.from_bytes(packet[2:4], 'big')
        flags = int.from_bytes(packet[4:6], 'big')
        return seq, ack, flags

    def send_data(self, data, window, addr):
        print("Data transfer:")
        chunks = [data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
        packets_in_flight = 0
        sliding_window = deque()
        while self.seq <= len(chunks):
            while packets_in_flight < window and self.seq+packets_in_flight <= len(chunks):
                chunk = chunks[self.seq-1 + packets_in_flight]
                packet = self.create_packet(self.seq+packets_in_flight, self.ack, 4, chunk)
                self.sock.sendto(packet, addr)
                sliding_window.append(self.seq+packets_in_flight)
                if len(sliding_window) > window: sliding_window.popleft()
                print(f"{datetime.now().time()} -- packet with seq = {self.seq+packets_in_flight} sent, sliding window = {list(sliding_window)}")
                packets_in_flight += 1
            try:
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)
                if flags == 4 and self.ack == seq and self.seq+1 == ack:
                    print(f"{datetime.now().time()} -- ACK for packet with seq = {self.seq} received")
                    self.seq = ack
                    packets_in_flight -= 1
            except timeout:
                print(f"Retransmission timeout. ACK not received.")
                packets_in_flight = 0
        print("Data transfer finished")
    
    def receive_data(self, addr, discard):
        self.sock.settimeout(None)
        data = b''
        while True:
            packet = self.sock.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0]
            chunk = packet[HEADER_SIZE:]
            seq, ack, flags = self.extract_header(packet)
            if seq == discard:
                discard = None
            elif flags == 4 and self.seq == ack and self.ack == seq and chunk:
                print(f"{datetime.now().time()} -- packet with seq = {seq} received")
                self.ack += 1
                packet = self.create_packet(self.seq, self.ack, 4)
                self.sock.sendto(packet, addr)
                print(f"{datetime.now().time()} -- ACK for packet with seq = {seq} sent")
                data += chunk
            elif flags == 6 and self.seq == ack and self.ack == seq:
                self.ack = seq+1
                self.__receiver_close_connection()
                break
            elif flags == 4:
                print(f"{datetime.now().time()} -- out-of-order packet with seq = {seq} received")
        return data
    
    def close_connection(self):
        print("Connection teardown. Four way handshake")
        packet = self.create_packet(self.seq, self.ack, 6)
        while True:
            self.sock.sendto(packet, self.server_addr)
            print("FIN packet sent")
            try:        
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)
                if flags == 4 and ack == self.seq+1 and self.ack == seq:
                    print("ACK packet received")
                    self.seq = ack
                    break
                else:
                    break
            except timeout:
                print("ACK not received in time. Retransmitting packet")
                continue
        
        while True:
            packet = self.sock.recvfrom(HEADER_SIZE)[0] # Receive FIN-ACK
            seq, ack, flags = self.extract_header(packet)
            if flags == 6 and ack == self.seq and seq == self.ack:
                print("FIN packet received")
                self.ack = seq+1
                packet = self.create_packet(self.seq, self.ack, 4)
                self.sock.sendto(packet, self.server_addr) # Send ACK
                print("ACK packet sent")
                print("Connection closes")
                self.sock.close()
                break
    
    def __receiver_close_connection(self):
        print("FIN packet received")
        packet = self.create_packet(self.seq, self.ack, 4)
        self.sock.sendto(packet, self.client_addr) # Send ACK
        print("ACK packet sent")

        self.sock.settimeout(TIMEOUT)
        while True:
            packet = self.create_packet(self.seq, self.ack, 6)
            self.sock.sendto(packet, self.client_addr) # Send FIN-ACK
            print("FIN packet sent")
            try:
                packet = self.sock.recvfrom(HEADER_SIZE)[0] # Receive ACK
                seq, ack, flags = self.extract_header(packet)
                if flags == 4 and ack == self.seq+1 and self.ack == seq:
                    print("ACK packet received")
                    self.seq = ack
                    print("Connection closes")
                    self.sock.close()
                    break
                else:
                    break
            except timeout:
                print("Timeout. ACK packet not received in time")
                continue    
