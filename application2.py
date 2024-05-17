from socket import *
import argparse
import ipaddress
from datetime import datetime

CHUNK_SIZE = 994
HEADER_SIZE = 6
TIMEOUT = 0.5

class DRTP():
    def __init__(self, server_addr, file, window):
        # Assumes starting seq is 0 on client and server
        self.seq = 0
        self.ack = 0
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.server_addr = server_addr
        self.file = file
        self.window = window

    def create_packet(self, seq, ack, flags):
        return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big')

    def extract_header(self, packet):
        seq = int.from_bytes(packet[:2], 'big')
        ack = int.from_bytes(packet[2:4], 'big')
        flags = int.from_bytes(packet[4:6], 'big')
        return seq, ack, flags

    def send_data(self, data, window, addr):
        chunks = [data[i:i+window] for i in range(0, len(data), window)]
        packets_in_flight, acked_packets = 0, 0
        while acked_packets < len(chunks):
            while packets_in_flight < window and acked_packets+packets_in_flight < len(chunks):
                chunk = chunks[acked_packets+packets_in_flight]
                packet = self.create_packet(self.seq, self.ack, 4, chunk)
                expected_packet = self.create_packet(self.ack, self.seq+1+CHUNK_SIZE, 4)
                socket.sendto(packet, addr)
                packets_in_flight += 1
            try:
                packet = socket.recvfrom(HEADER_SIZE)[0]
                if packet == expected_packet:
                    print("Received ACK")
                    acked_packets += 1
                    packets_in_flight -= 1
            except timeout:
                packets_in_flight = 0
    
    def receive_data(self, window):
        with open(self.file, 'wb') as f:
            packet = self.sock.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0] # Receive header and data
            while len(packet) > HEADER_SIZE:
                packet = self.sock.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0] # Receive header and data
                f.write(packet[HEADER_SIZE:])
                self.sock.sendto(self.create_packet(self.ack, self.seq+CHUNK_SIZE, 4), self.client_addr) # Send ACK
        
class Server(DRTP):
    def __init__(self, server_addr, file, window):
        super().__init__(server_addr, file, window)
        self.client_addr = None
        self.sock.bind(server_addr)
    
    def listen(self):
        # Wait for SYN from client
        while True:
            packet, self.client_addr = self.sock.recvfrom(HEADER_SIZE)
            self.ack, self.seq, flags = self.extract_header(packet)
            self.ack += 1
            # Check if received packet is a SYN packet
            if flags == 8:
                print("SYN packet is received")
                break
    
    def accept(self):
        self.sock.settimeout(TIMEOUT)
        packet = self.create_packet(self.seq, self.ack, 12)
        while True:
            self.sock.sendto(packet, self.client_addr)
            print("SYN-ACK packet is sent")
            try:
                # Wait for ACK from client
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                # Check if received packet is an ACK packet
                expected_packet = self.create_packet(self.ack, self.seq+1, 4)
                if packet == expected_packet:
                    self.seq += 1
                    print("ACK packet is received")
                    break
            except timeout:
                print("Timeout. ACK packet not received in time")
                continue

    def close_connection(self):
        expected_packet = self.create_packet(self.ack, self.seq, 6)
        while True:
            packet = self.sock.recvfrom(HEADER_SIZE)[0] # Receive FIN-ACK
            if packet == expected_packet:
                print("FIN packet is received")
                self.ack += 1
                packet = self.create_packet(self.seq, self.ack, 4)
                self.sock.sendto(packet, self.client_addr) # Send ACK
                print("ACK packet is sent")
                print(f"seq={self.seq} ack={self.ack}")
                break
            else:
                print("Not expected packet")

        while True:
            packet = self.create_packet(self.seq, self.ack, 6)
            self.sock.sendto(packet, self.client_addr) # Send FIN-ACK
            print("FIN packet is sent")
            print(f"seq={self.seq} ack={self.ack} flags={6}")
            expected_packet = self.create_packet(self.ack, self.seq+1, 4)
            try:
                packet = self.sock.recvfrom(HEADER_SIZE)[0] # Receive ACK
                if packet == expected_packet:
                    print("ACK packet is received")
                    print("Connection closes")
                    self.sock.close()
                else:
                    break
            except timeout:
                print("Timeout. ACK packet not received in time")
                continue

class Client(DRTP):
    def __init__(self, server_addr, file, window):
        super().__init__(server_addr, file, window)
        self.sock.settimeout(TIMEOUT)
    
    def connect(self):
        # Send SYN packet to server and receive SYN-ACK packet from server
        packet = self.create_packet(self.seq, self.ack, 8)
        expected_packet = self.create_packet(self.ack, self.seq+1, 12)
        while True:
            self.sock.sendto(packet, self.server_addr)
            print("SYN packet is sent")
            try:
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                if packet == expected_packet:
                    print("SYN-ACK packet is received")
                    self.seq+=1
                    break
            except timeout:
                print("ACK not received in time. Retransmitting packet")
                continue

        packet = self.create_packet(self.seq, self.ack, 4)
        self.sock.sendto(packet, self.server_addr)
        print("ACK packet is sent")
        print(f"seq={self.seq} ack={self.ack}")

    def close_connection(self):
        packet = self.create_packet(self.seq, self.ack, 6)
        expected_packet = self.create_packet(self.ack, self.seq+1, 4)
        while True:
            self.sock.sendto(packet, self.server_addr)
            print("FIN packet is sent")
            print(f"seq={self.seq} ack={self.ack}")
            try:        
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                if packet == expected_packet:
                    print("ACK packet is received")
                    self.seq += 1
                    break
                else:
                    break
            except timeout:
                print("ACK not received in time. Retransmitting packet")
                continue
        
        expected_packet = self.create_packet(self.ack, self.seq, 6)
        while True:
            packet = self.sock.recvfrom(HEADER_SIZE)[0] # Receive FIN-ACK
            if packet == expected_packet:
                print("FIN packet is received")
                self.ack += 1
                packet = self.create_packet(self.seq, self.ack, 4)
                self.sock.sendto(packet, self.server_addr) # Send ACK
                print("ACK packet is sent")
                print("Connection closes")
                self.sock.close()
                break
            else:
                seq, ack, flags = self.extract_header(packet)
                print(f"seq={seq} ack={ack} flags={flags}")
                seq, ack, flags = self.extract_header(expected_packet)
                print(f"seq={seq} ack={ack} flags={flags}")

def run_server(server_addr, file, window):
    server = Server(server_addr, file, window)
    server.listen()
    server.accept()
    #data = server.receive_data()
    #with open(file, 'wb') as f:
    #    f.write()
    server.close_connection()

def run_client(server_addr, file, window):
    client = Client(server_addr, file, window)
    client.connect()
    #with open(file, 'rb') as f:
    #    data = f.read()
    #    client.send_data(data)
    client.close_connection()

if __name__ == "__main__":
    # Uses argparse to parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', help='Enable server mode', action='store_true')
    parser.add_argument('-c', '--client', help='Enable client mode', action='store_true')
    parser.add_argument('-p', '--port', help='Select server port number in the range [1024, 65535]. Default: 8088', type=int, default=8088)
    parser.add_argument('-i', '--ip', help='Select server IP-address. Default: 127.0.0.1', type=str, default='127.0.0.1')
    parser.add_argument('-f', '--file', help='Specify filename', required=True)
    parser.add_argument('-w', '--window', help='Sliding window size. Default: 3', type=int, default=3)
    args = parser.parse_args()

    # Uses ipaddress library to validate the IP
    # Takes an ip. If the ip is invalid IPv4Address() will cast an exception
    # and the function will return False
    def valid_ip(ip):
        try:
            ipaddress.IPv4Address(ip)
            return True
        except:
            return False

    # Handles errors/exceptions
    if args.port not in range(1024, 65536):
        print('Invalid port. It must be within range [1024, 65535]')
    elif not valid_ip(args.ip):
        print('Invalid IPv4 address.')
    elif args.server and args.client:
        print('You cannot enable server and client mode at the same time')
    elif not (args.server or args.client):
        print('You have to enable either server or client mode')
    elif args.server:
        run_server((args.ip, args.port), args.file, args.window)
    elif args.client:
        run_client((args.ip, args.port), args.file, args.window)