from socket import *
import argparse
import ipaddress

def server(ip, port, file):
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind((ip, port))
    data = server_socket.recvfrom(1024)[0]
    if data.decode() == 'start':
        with open(file, 'wb') as f:
            while True:
                data = server_socket.recvfrom(1024)[0]
                if data.decode() == 'end': break
                f.write(data)
    server_socket.close()


def client(ip, port, file):
    client_socket = socket(AF_INET, SOCK_DGRAM)
    with open(file, 'rb') as f:
        client_socket.sendto('start'.encode(), (ip, port))
        data = f.read(1024)
        while data:
            client_socket.sendto(data, (ip, port))
            data = f.read(1024)
    client_socket.sendto('end'.encode(), (ip, port))
    client_socket.close()

def parse_arguments():
    # Uses argparse to parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', help='Enable server mode', action='store_true')
    parser.add_argument('-c', '--client', help='Enable client mode', action='store_true')
    parser.add_argument('-p', '--port', help='Select server port number in the range [1024, 65535]', type=int, required=True)
    parser.add_argument('-i', '--ip', help='Select server IP-address', type=str, required=True)
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