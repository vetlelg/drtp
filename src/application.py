import argparse
import ipaddress
from server import Server
from client import Client
from socket import *

def run_server(server_addr, file, discard=None):
    """
    Start the server application

    Parameters
    ----------
    server_addr : tuple (ip, port)
        Server IP and port number as a tuple
    file : str
        Filepath or name of file
    discard : int or None
        The sequence number of a packet that should be discarded by the receiver
    """
    
    try:
        # Create server object
        server = Server(server_addr)

        # Listen for connections. Receives SYN from client
        server.listen()

        # Continues three way handshake. Sends SYN-ACK and receives ACK from client
        client_addr = server.accept()

        # Start receiving data. Stop receiving when FIN is received from client
        data = server.receive_data(client_addr, discard)

        # Writes received data to file
        with open(file, 'wb') as f:
            f.write(data)

    # Handle any exceptions that lower-level functions may raise
    except Exception as e:
        print(f"Error occurred on the server: {e}")
    finally:
        # Clean up after the server is finished running
        server.sock.close()

def run_client(server_addr, file, window):
    """
    Start the client application

    Parameters
    ----------
    server_addr : tuple (ip, port)
        Server IP and port number as a tuple
    file : str
        Filepath or name of file
    window : int
        Size of sliding window
    """

    try:
        # Create client object
        client = Client(server_addr)

        # Initiate three way handshake / Connection establishment
        # Sends SYN and receives SYN-ACK from server
        client.connect()

        # Read file and start sending data
        with open(file, 'rb') as f:
            data = f.read()
            client.send_data(data, window, server_addr)

        # Initiate two way handshake / Connection teardown
        # Send FIN and receive ACK from server
        client.close_connection()

    except FileNotFoundError:
        print(f"File {file} not found.")

    # Handle any exceptions that lower-level functions may raise
    except Exception as e:
        print(f"Error occurred on the client: {e}")
    finally:
        # Clean up after the client is finished running
        client.sock.close()

if __name__ == "__main__":
    # The following code for parsing arguments was used by me in the obligatory assignments earlier this year.
    # See the citation list in the project report (Gundersen 2024)
    # Uses argparse to parse the arguments from the command line
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

    # Handles errors/exceptions for command line arguments
    if args.port not in range(1024, 65536):
        print('Invalid port. It must be within range [1024, 65535]')
    elif not valid_ip(args.ip):
        print('Invalid IPv4 address.')
    elif args.server and args.client:
        print('You cannot enable server and client mode at the same time')
    elif not (args.server or args.client):
        print('You have to enable either server or client mode')
    elif args.server:
        run_server((args.ip, args.port), args.file, args.discard)
    elif args.client:
        run_client((args.ip, args.port), args.file, args.window)