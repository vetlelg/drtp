from socket import *
import argparse
import ipaddress


chunk_size = 994
header_size = 6

def server(ip, port, file):
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind((ip, port))

    # Establish connection. Three way handshake
    data, addr = server_socket.recvfrom(header_size) # Receive SYN
    seq, ack, flags = header_from_bytes(data)
    if flags & 0x8: # Check SYN
        print("SYN packet is received")
        server_socket.sendto(header_to_bytes(0, seq+1, 0xC), addr) # Send SYN-ACK
        print("SYN-ACK packet is sent")
        data = server_socket.recvfrom(header_size)[0] # Receive ACK
        seq, ack, flags = header_from_bytes(data)
        if flags & 0x4: # Check ACK
            print("ACK packet is received")

            # Connection established. Start receiving data...
            print("Connection established")
            with open(file, 'wb') as f:
                while True:
                    data = server_socket.recvfrom(header_size+chunk_size)[0] # Receive header and data
                    seq, ack, flags = header_from_bytes(data)
                    if len(data) <= header_size: # Check if there is any data
                        break
                    f.write(data[header_size:])
                    server_socket.sendto(header_to_bytes(ack, seq+chunk_size, 0x4), addr) # Send ACK
                
            # Terminate connection. Four way handshake
            if flags & 0x6: # Check FIN-ACK
                print("FIN packet is received")
                server_socket.sendto(header_to_bytes(ack, seq+1, 0x4), addr) # Send ACK
                print("ACK packet is sent")
                server_socket.sendto(header_to_bytes(ack, seq+1, 0x6), addr) # Send FIN-ACK
                print("FIN packet is sent")
                data = server_socket.recvfrom(header_size)[0] # Receive ACK
                seq, ack, flags = header_from_bytes(data)
                if flags & 0x4:
                    print("ACK packet is received")
                    print("Connection closes")
                    server_socket.close()

def client(ip, port, file):
    client_socket = socket(AF_INET, SOCK_DGRAM)

    # Establish connection. Three way handshake
    client_socket.sendto(header_to_bytes(0, 0, 0x8), (ip, port)) # Send SYN
    print("SYN packet is sent")
    data = client_socket.recvfrom(header_size)[0] # Receive SYN-ACK
    seq, ack, flags = header_from_bytes(data)
    if flags & 0xC: # Check SYN-ACK
        print("SYN-ACK packet is received")
        client_socket.sendto(header_to_bytes(ack, seq+1, 0x4), (ip, port)) # Send ACK
        print("ACK packet is sent")

        # Connection established. Start sending data...
        print("Data Transfer:")
        with open(file, 'rb') as f:
            data = f.read(chunk_size)
            while data:
                client_socket.sendto(header_to_bytes(ack, seq+1, 0x4) + data, (ip, port)) # Send data
                data = client_socket.recvfrom(header_size)[0] # Receive ACK
                seq, ack, flags = header_from_bytes(data)
                if flags & 0x4:
                    data = f.read(chunk_size)    
        print("Data transfer finished")

        # Terminate connection. Four way handshake
        print("Connection Teardown:")
        client_socket.sendto(header_to_bytes(ack, seq, 0x6), (ip, port)) # Send FIN-ACK
        print("FIN packet is sent")
        data = client_socket.recvfrom(header_size)[0] # Receive ACK
        seq, ack, flags = header_from_bytes(data)
        if flags & 0x4:
            print("ACK packet is received")
            data = client_socket.recvfrom(header_size)[0] # Receive FIN-ACK
            print("FIN packet is received")
            seq, ack, flags = header_from_bytes(data)
            if flags & 0x6:
                print("ACK packet is received")
                client_socket.sendto(header_to_bytes(ack, seq+1, 0x4), (ip, port)) # Send ACK
                print("Connection closes")
                client_socket.close()


def header_to_bytes(seq, ack, flags):
    return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big')

def header_from_bytes(data):
    seq = int.from_bytes(data[:2], 'big')
    ack = int.from_bytes(data[2:4], 'big')
    flags = int.from_bytes(data[4:6], 'big')
    return seq, ack, flags


def parse_arguments():
    # Uses argparse to parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', help='Enable server mode', action='store_true')
    parser.add_argument('-c', '--client', help='Enable client mode', action='store_true')
    parser.add_argument('-p', '--port', help='Select server port number in the range [1024, 65535]. Default: 8088', type=int, default=8088)
    parser.add_argument('-i', '--ip', help='Select server IP-address. Default: 10.0.0.2', type=str, default='10.0.0.2')
    parser.add_argument('-f', '--file', help='Specify filename', required=True)
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