from socket import *
import argparse
import ipaddress

CHUNK_SIZE = 994
HEADER_SIZE = 6
window_size = 3
TIMEOUT = 0.5 # 500ms = 0.5s
        
def server(ip, port, file):
    seq, ack = 0, 0
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind((ip, port))

    # Establish connection. Three way handshake
    # Wait for SYN from client
    expected_packet = create_packet(seq, ack, 8)
    while True:
        packet, addr = server_socket.recvfrom(HEADER_SIZE)
        seq, ack, flags = extract_header(packet)
        # Check if received packet is a SYN packet
        if packet == expected_packet:
            print("SYN packet is received")
            break
    
    server_socket.settimeout(timeout)
    packet = create_packet(ack, seq+1, 12)
    expected_packet = create_packet()
    while True:
        try:
            # Send SYN-ACK to client
            server_socket.sendto(packet, addr)
            print("SYN-ACK packet is sent")
            # Wait for ACK from client
            packet = server_socket.recvfrom(HEADER_SIZE)[0]
            # Check if received packet is an ACK packet
            if packet == expected_packet:
                print("ACK packet is received")
                print("Connection established")
                break
        except socket.timeout:
            print("Timeout. ACK packet not received in time")
            continue
    
    seq, ack = extract_header(packet)
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

def client(addr, file):
    client_socket = socket(AF_INET, SOCK_DGRAM)

    # Establish connection. Three way handshake
    # Send SYN packet to server and receive SYN-ACK packet from server
    seq, ack = 0, 0
    packet = create_packet(seq, ack, 8)
    expected_packet = create_packet(ack, seq+1, 12)
    while True:
        try:
            client_socket.sendto(packet, addr)
            print("SYN packet is sent")
            packet = client_socket.recvfrom(HEADER_SIZE)[0]
            if packet == expected_packet:
                print("SYN-ACK packet is received")
                break
        except socket.timeout:
            print("ACK not received in time. Retransmitting packet")
            continue
    
    # Return ACK packet to server
    seq, ack = extract_header(packet)
    packet = create_packet(ack, seq+1, 4)
    client_socket.sendto(packet, addr)
    print("ACK packet is sent")
    print("Connection established")

    # Connection established. Start sending data
    print("Data Transfer:")
    with open(file, 'rb') as f:
        data = f.read(CHUNK_SIZE)
        while data:
            packet = create_packet(ack, seq+1, 4, data)
            expected_packet = create_packet(seq+1, seq+1+CHUNK_SIZE, 4)
            packet = send_packet(client_socket, addr, packet, expected_packet)
            seq, ack = extract_header(packet)
            if expected_packet == packet: data = f.read(CHUNK_SIZE)

    # Terminate connection. Four way handshake
    # Send FIN-ACK packet and receive ACK packet from server
    print("Connection Teardown:")
    packet = create_packet(ack, seq, 6)
    expected_packet = create_packet(ack, seq+1, 4)
    while True:
        try:
            client_socket.sendto(packet, addr)
            print("FIN packet is sent")
            packet = client_socket.recvfrom(HEADER_SIZE)[0]
            if packet == expected_packet:
                print("ACK packet is received")
                break
        except socket.timeout:
            print("ACK not received in time. Retransmitting packet")
            continue
    
    expected_packet = create_packet(ack, seq+1, 6)
    while True:
        packet = client_socket.recvfrom(HEADER_SIZE)[0] # Receive FIN-ACK
        if packet == expected_packet:
            print("FIN packet is received")
            seq, ack = extract_header(packet)
            packet = create_packet(ack, seq+1, 4)
            client_socket.sendto(packet, addr) # Send ACK
            print("ACK packet is sent")
            print("Connection closes")
            client_socket.close()
            break

def create_packet(seq, ack, flags, data = b''):
    return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + data

def extract_header(packet):
    seq = int.from_bytes(packet[:2], 'big')
    ack = int.from_bytes(packet[2:4], 'big')
    return seq, ack


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
        client((args.ip, args.port), args.file)

def main():
    parse_arguments()

if __name__ == "__main__":
    main()