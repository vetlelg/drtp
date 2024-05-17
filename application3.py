from socket import *
import argparse
import ipaddress

CHUNK_SIZE = 994
HEADER_SIZE = 6
window_size = 3
TIMEOUT = 0.5 # 500ms = 0.5s
        
def server(ip, port, file):
    seq, ack, flags = None, None, None
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind((ip, port))

    # Establish connection. Three way handshake
    # Wait for SYN from client
    while True:
        packet, addr = server_socket.recvfrom(HEADER_SIZE)
        seq, ack, flags = extract_header(packet)
        # Check if received packet is a SYN packet
        if flags == 8:
            print("SYN packet is received")
            break
    
    server_socket.settimeout(timeout)
    while True:
        try:
            # Send SYN-ACK to client
            server_socket.sendto(create_packet(0, seq+1, 12), addr)
            print("SYN-ACK packet is sent")
            # Wait for ACK from client
            packet = server_socket.recvfrom(HEADER_SIZE)[0]
            seq, ack, flags = extract_header(packet)
            # Check if received packet is an ACK packet
            if flags == 4:
                print("ACK packet is received")
                print("Connection established")
                break
        except socket.timeout:
            print("Timeout. ACK packet not received in time")
            continue
    
    # Start receiving data
    with open(file, 'wb') as f:
        while True:
            packet = server_socket.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0] # Receive header and data
            seq, ack, flags = extract_header(packet)
            if len(packet) <= HEADER_SIZE and flags == 2: # Check if there is any data
                print("FIN packet is received")
                break
            f.write(packet[HEADER_SIZE:])
            server_socket.sendto(create_packet(ack, seq+CHUNK_SIZE, 4), addr) # Send ACK
    
    
    # Terminate connection. Four way handshake
    server_socket.sendto(create_packet(ack, seq+1, 4), addr) # Send ACK
    print("ACK packet is sent")

    while True:
        try:
            server_socket.sendto(create_packet(ack, seq+1, 6), addr) # Send FIN-ACK
            print("FIN packet is sent")
            packet = server_socket.recvfrom(HEADER_SIZE)[0] # Receive ACK
            seq, ack, flags = extract_header(packet)
            if flags == 4:
                print("ACK packet is received")
                print("Connection closes")
                server_socket.close()
        except socket.timeout:
            print("Timeout. ACK packet not received in time")
            continue



def client(ip, port, file):
    client_socket = socket(AF_INET, SOCK_DGRAM)

    # Establish connection. Three way handshake
    while True:
        try:
            # Send SYN packet to server
            client_socket.sendto(create_packet(0, 0, 8), (ip, port))
            print("SYN packet is sent")
            # Receive SYN-ACK packet from server
            packet = client_socket.recvfrom(HEADER_SIZE)[0]
            seq, ack, flags = extract_header(packet)
            # Check if received packet is SYN-ACK
            if flags == 12:
                print("SYN-ACK packet is received")
                break
        except socket.timeout:
            print("Timeout. SYN-ACK packet not received within time limit")
        
        # Send ACK packet to server
        client_socket.sendto(create_packet(ack, seq+1, 4), (ip, port))
        print("ACK packet is sent")

        # Connection established. Start sending data...
        print("Data Transfer:")
        with open(file, 'rb') as f:
            data = f.read(CHUNK_SIZE)
            while data:
                client_socket.sendto(create_packet(ack, seq+1, 4, data), (ip, port)) # Send data
                packet = client_socket.recvfrom(HEADER_SIZE)[0] # Receive ACK
                seq, ack, flags = extract_header(packet)
                if flags == 4:
                    print("ACK received")
                    data = f.read(CHUNK_SIZE)   
    
        # Terminate connection. Four way handshake
        print("Data transfer finished. Connection Teardown.")
        while True:
            try:
                client_socket.sendto(create_packet(ack, seq, 6), (ip, port)) # Send FIN-ACK
                print("FIN packet is sent")
                packet = client_socket.recvfrom(HEADER_SIZE)[0] # Receive ACK
                seq, ack, flags = extract_header(packet)
                if flags == 4:
                    print("ACK packet is received")
                    break
            except socket.timeout:
                print("Timeout. ACK not received")
                continue
            
        while True:
            packet = client_socket.recvfrom(HEADER_SIZE)[0] # Receive FIN-ACK
            seq, ack, flags = extract_header(packet)
            if flags == 6:
                print("FIN packet is received")
                client_socket.sendto(create_packet(ack, seq+1, 4), (ip, port)) # Send ACK
                print("ACK packet is sent")
                print("Connection closes")
                client_socket.close()

def send_packet(socket, packet, expected_ack_packet, addr):
    while True:
        try:
            socket.sendto(packet, addr)
            print_packet(packet)
            packet = socket.recvfrom(HEADER_SIZE)[0]
            if packet == expected_ack_packet:
                print_packet(packet)
                return packet
        except socket.timeout:
            print("Timeout. ACK not received in time.")

def print_packet(packet):
    seq, ack, flags = extract_header(packet)
    print(f"seq={seq}, ack={ack}, flags={flags}")
    

def create_packet(seq, ack, flags, data = b''):
    return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + data

def extract_header(packet):
    seq = int.from_bytes(packet[:2], 'big')
    ack = int.from_bytes(packet[2:4], 'big')
    flags = int.from_bytes(packet[4:6], 'big')
    return seq, ack, flags


def parse_arguments():
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
        server(args.ip, args.port, args.file)
    elif args.client:
        client(args.ip, args.port, args.file)

def main():
    parse_arguments()

if __name__ == "__main__":
    main()