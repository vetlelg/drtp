from socket import *
import argparse
import ipaddress

client_seq = 0
server_seq = 0

def server(ip, port, file):
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind((ip, port))
    data, addr = server_socket.recvfrom(6) # Receive SYN
    seq, ack, flags = header_from_bytes(data)
    if flags & 0x8: # Check SYN
        server_socket.sendto(header_to_bytes(server_seq, seq+1, 0x6), addr) # Send SYN-ACK
        data = server_socket.recvfrom(6)[0] # Receive ACK
        seq, ack, flags = header_from_bytes(data)
        if flags & 0x4: # Check ACK
            with open(file, 'wb') as f:
                while True:
                    data = server_socket.recvfrom(1000)[0] # Receive data and FIN
                    seq, ack, flags = header_from_bytes(data)
                    if len(data) <= 6: # Check if there is any data
                        if flags & 0x2: break # Check FIN
                    else:
                        f.write(data[6:])
                        server_socket.sendto(header_to_bytes(ack, seq+1, 0x4), addr) # Send ACK
    server_socket.close()

def client(ip, port, file):
    client_socket = socket(AF_INET, SOCK_DGRAM)
    client_socket.sendto(header_to_bytes(client_seq, 0, 0x8), (ip, port)) # Send SYN
    data = client_socket.recvfrom(6)[0] # Receive SYN-ACK
    seq, ack, flags = header_from_bytes(data)
    if flags & 0x8 and flags & 0x4: # Check SYN-ACK
        client_socket.sendto(header_to_bytes(ack, seq+1, 0x4), (ip, port)) # Send ACK
        with open(file, 'rb') as f:
            data = f.read(994)
            while data:
                client_socket.sendto(header_to_bytes(ack, seq+1, 0x0) + data, (ip, port)) # Send data
                data = client_socket.recvfrom(6)[0] # Receive ACK
                seq, ack, flags = header_from_bytes(data)
                if flags & 0x4:
                    data = f.read(994)
    
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