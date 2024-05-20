from socket import *
from datetime import datetime
import time
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

    def calculate_throughput(self, bytes, time_elapsed):
                bits = len(bytes) * 8
                bps = bits / time_elapsed
                return round(bps / 1_000_000, 2)

    def create_packet(self, seq, ack, flags, chunk = b''):
        return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + chunk

    def extract_header(self, packet):
        seq = int.from_bytes(packet[:2], 'big')
        ack = int.from_bytes(packet[2:4], 'big')
        flags = int.from_bytes(packet[4:6], 'big')
        return seq, ack, flags

    def send_data(self, data, window, addr):
        print("Start sending data:")
        chunks = [data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
        packets_in_flight = 0
        sliding_window = deque()
        while self.seq <= len(chunks):
            while packets_in_flight < window and self.seq+packets_in_flight <= len(chunks):
                chunk = chunks[self.seq-1 + packets_in_flight]
                packet = self.create_packet(self.seq+packets_in_flight, self.ack, 4, chunk)
                try:
                    self.sock.sendto(packet, addr)
                except Exception:
                    print(f"{datetime.now().time()} -- Error sending packet with seq = {self.seq+packets_in_flight}. Retransmitting packet")
                    continue
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
                print(f"{datetime.now().time()} -- Retransmission timeout. ACK not received.")
                packets_in_flight = 0
            except Exception as e:
                print(f"{datetime.now().time()} -- Unexpected error when receiving ACK.")
                packets_in_flight = 0
        print("Finished sending data")
    
    def receive_data(self, addr, discard):
        print("Start receiving data")
        start_time = time.time()
        self.sock.settimeout(None)
        data = b''
        bytes_received = b''
        while True:
            try:
                packet = self.sock.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0]
            except Exception:
                print(f"{datetime.now().time()} -- Unexpected error when receiving data. Trying again")
                continue
            bytes_received += packet
            chunk = packet[HEADER_SIZE:]
            seq, ack, flags = self.extract_header(packet)
            if seq == discard:
                discard = None
            elif flags == 4 and self.seq == ack and self.ack == seq and chunk:
                try:
                    print(f"{datetime.now().time()} -- packet with seq = {seq} received")
                    packet = self.create_packet(self.seq, self.ack+1, 4)
                    self.sock.sendto(packet, addr)
                    self.ack += 1
                    print(f"{datetime.now().time()} -- ACK for packet with seq = {seq} sent")
                    data += chunk
                except Exception:
                    print(f"{datetime.now().time()} -- Unexpected error when sending ACK for packet with seq = {seq}. Keep receiving data")
            elif flags == 6 and self.seq == ack and self.ack == seq:
                try:
                    time_elapsed = time.time() - start_time
                    print(f"Throughput: {self.calculate_throughput(bytes_received, time_elapsed)} Mbps")
                    print("FIN packet received")
                    packet = self.create_packet(self.seq, self.ack+1, 4)
                    self.sock.sendto(packet, addr)
                    print("ACK packet sent")
                    self.ack += 1
                    print("Connection closes")
                    self.sock.close()
                    return data
                except Exception:
                    print(f"{datetime.now().time()} -- Unexpected error when sending FIN ACK packet. Keep receiving data")
            elif flags == 4:
                print(f"{datetime.now().time()} -- out-of-order packet with seq = {seq} received")
            
    
    def close_connection(self):
        print("Connection teardown. Four way handshake")
        packet = self.create_packet(self.seq, self.ack, 6)
        while True:
            try:
                self.sock.sendto(packet, self.server_addr)
                print("FIN packet sent")     
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)
                if flags == 4 and ack == self.seq+1 and self.ack == seq:
                    print("ACK packet received")
                    self.seq = ack
                    print("Connection closes")
                    self.sock.close()
                    break
            except timeout:
                print("Graceful connection teardown failed. ACK not received. Closing connection")
                raise
            except Exception as e:
                print(f"Unexpected error occurred during connection teardown.")
                raise
