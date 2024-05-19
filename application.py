import argparse
import ipaddress
from datetime import datetime
from server import Server
from client import Client

def run_server(server_addr, file, window, discard=None):
    server = Server(server_addr)
    server.listen()
    client_addr = server.accept()
    data = server.receive_data(client_addr, discard)
    with open(file, 'wb') as f:
        f.write(data)

def run_client(server_addr, file, window):
    client = Client(server_addr)
    client.connect()
    with open(file, 'rb') as f:
        data = f.read()
        client.send_data(data, window, server_addr)
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
    parser.add_argument('-d', '--discard', help='The server will discard the packet with seq number provided to test retransmission of packets.', type=int)
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
        run_server((args.ip, args.port), args.file, args.window, args.discard)
    elif args.client:
        run_client((args.ip, args.port), args.file, args.window)