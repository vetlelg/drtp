from socket import *
import argparse
import ipaddress

CHUNK_SIZE = 994
HEADER_SIZE = 6
TIMEOUT = 0.5

class DRTP():
    def __init__(self, server_addr, file, window):
        # Assumes starting seq is 0 on client and server
        self.seq = 0
        self.ack = 0
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.server_addr = server_addr
        self.file = file
        self.window = window
        self.sliding_window = list(range(window*2))

    def create_packet(seq, ack, flags, data = b''):
        return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + data

    def extract_header(packet):
        seq = int.from_bytes(packet[:2], 'big')
        ack = int.from_bytes(packet[2:4], 'big')
        return seq, ack
    
    def send(self, data, window, addr):
        while data:
            segment = data[:CHUNK_SIZE*window]
            data = data[CHUNK_SIZE*window:]
            for i in range(window):
                chunk = data[:CHUNK_SIZE]
                data = data[CHUNK_SIZE:]
                packet = self.create_packet(self.ack, self.seq+1, 4, chunk)
                expected_packet = self.create_packet(seq+1, self.seq+1+len(chunk), 4)
                socket.sendto(packet, addr)
                try:
                    packet = socket.recvfrom(HEADER_SIZE)[0]
                    if packet == expected_packet:
                        print("ACK packet received")
                except socket.timeout:
                    print("ACK not received in time. Retransmitting")
                if not data: break
            
        # with open(self.file, 'rb') as f:
        #     data = f.read(CHUNK_SIZE)
        #     while data:
        #         packet = self.create_packet(ack, seq+1, 4, data)
        #         expected_packet = self.create_packet(seq+1, seq+1+CHUNK_SIZE, 4)
        #         # Insert sending of data
        #         seq, ack = self.extract_header(packet)
        #         if expected_packet == packet: data = f.read(CHUNK_SIZE)
    
    def receive(self, window):
        with open(self.file, 'wb') as f:
            packet = self.socket.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0] # Receive header and data
            while len(packet) > HEADER_SIZE:
                packet = self.socket.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0] # Receive header and data
                f.write(packet[HEADER_SIZE:])
                self.socket.sendto(self.create_packet(self.ack, self.seq+CHUNK_SIZE, 4), self.client_addr) # Send ACK
    
    def close_connection(self):
        packet = self.create_packet(ack, seq, 6)
        expected_packet = self.create_packet(self.ack, self.seq+1, 4)
        while True:
            try:
                self.socket.sendto(packet, addr)
                print("FIN packet is sent")
                packet = self.socket.recvfrom(HEADER_SIZE)[0]
                if packet == expected_packet:
                    print("ACK packet is received")
                    break
            except socket.timeout:
                print("ACK not received in time. Retransmitting packet")
                continue
        
class Server(DRTP):
    def __init__(self, server_addr, file, window):
        super().__init__(server_addr, file, window)
        self.client_addr = None
        self.socket.bind(server_addr)
    
    def listen(self):
        # Wait for SYN from client
        expected_packet = self.create_packet(self.seq, self.ack, 8)
        while True:
            packet, self.client_addr = self.server_socket.recvfrom(HEADER_SIZE)
            self.seq, self.ack = self.extract_header(packet)
            # Check if received packet is a SYN packet
            if packet == expected_packet:
                print("SYN packet is received")
                break
    
    def accept(self):
        self.socket.settimeout(timeout)
        packet = self.create_packet(self.ack, self.seq+1, 12)
        expected_packet = self.create_packet(self.seq+1, self.ack+1)
        while True:
            try:
                # Send SYN-ACK to client
                self.socket.sendto(packet, self.client_addr)
                print("SYN-ACK packet is sent")
                # Wait for ACK from client
                packet = self.socket.recvfrom(HEADER_SIZE)[0]
                # Check if received packet is an ACK packet
                if packet == expected_packet:
                    self.seq, self.ack = self.extract_header(packet)
                    print("ACK packet is received")
                    break
            except socket.timeout:
                print("Timeout. ACK packet not received in time")
                continue

    def close_connection(self):
        self.socket.sendto(self.create_packet(ack, seq+1, 4), self.client_addr) # Send ACK
        print("ACK packet is sent")

        while True:
            try:
                self.socket.sendto(self.create_packet(ack, seq+1, 6), self.client_addr) # Send FIN-ACK
                print("FIN packet is sent")
                packet = self.socket.recvfrom(HEADER_SIZE)[0] # Receive ACK
                seq, ack, flags = self.extract_header(packet)
                if flags == 4:
                    print("ACK packet is received")
                    print("Connection closes")
                    self.socket.close()
            except socket.timeout:
                print("Timeout. ACK packet not received in time")
                continue

class Client(DRTP):
    def __init__(self, server_addr, file, window):
        super().__init__(server_addr, file, window)
    
    def connect(self):
        # Send SYN packet to server and receive SYN-ACK packet from server
        packet = self.create_packet(self.seq, self.ack, 8)
        expected_packet = self.create_packet(self.ack, self.seq+1, 12)
        while True:
            try:
                self.socket.sendto(packet, self.server_addr)
                print("SYN packet is sent")
                packet = self.socket.recvfrom(HEADER_SIZE)[0]
                if packet == expected_packet:
                    print("SYN-ACK packet is received")
                    break
            except socket.timeout:
                print("ACK not received in time. Retransmitting packet")
                continue

    def close_connection(self):
        packet = self.create_packet(ack, seq, 6)
        expected_packet = self.create_packet(ack, seq+1, 4)
        while True:
            try:
                self.socket.sendto(packet, self.server_addraddr)
                print("FIN packet is sent")
                packet = self.socket.recvfrom(HEADER_SIZE)[0]
                if packet == expected_packet:
                    print("ACK packet is received")
                    break
            except socket.timeout:
                print("ACK not received in time. Retransmitting packet")
                continue
        
        expected_packet = self.create_packet(ack, seq+1, 6)
        while True:
            packet = self.socket.recvfrom(HEADER_SIZE)[0] # Receive FIN-ACK
            if packet == expected_packet:
                print("FIN packet is received")
                seq, ack = self.extract_header(packet)
                packet = self.create_packet(ack, seq+1, 4)
                self.socket.sendto(packet, self.server_addr) # Send ACK
                print("ACK packet is sent")
                print("Connection closes")
                self.socket.close()
                break

def run_server():
    return

def run_client():
    return

if __name__ == "__main__":
    # Uses argparse to parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', help='Enable server mode', action='store_true')
    parser.add_argument('-c', '--client', help='Enable client mode', action='store_true')
    parser.add_argument('-p', '--port', help='Select server port number in the range [1024, 65535]. Default: 8088', type=int, default=8088)
    parser.add_argument('-i', '--ip', help='Select server IP-address. Default: 10.0.0.2', type=str, default='10.0.0.2')
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