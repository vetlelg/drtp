from socket import *
from datetime import datetime
import time
from collections import deque

CHUNK_SIZE = 994 # Number of bytes for the payload in each packet
HEADER_SIZE = 6  # Number of bytes for the header in each packet (2 bytes each for seq, ack and flags)
TIMEOUT = 0.5    # Number of seconds the sender should wait for an ACK before it times out

class Host():
    """
    This class represents a network host and is used for attributes and methods that are needed on both client and server.
    Client and Server class inherits from this class.

    Attributes
    ----------
    seq : int
        The sequence number of the next packet that will be sent.
    ack : int
        The acknowledgement number of the next packet that will be sent.
        This should be equal to the next expected sequence number from the connected host.
    sock : socket
        The host socket. Used for sending and receiving UDP packets.
    server_addr : tuple (ip, port)
        Contains the server IP and Port number in a tuple
    
    Methods
    -------
    calculate_throughput(bytes, time_elapsen)
        Calculates the throughput of the file transfer
    create_packet(seq, ack, flags, chunk = b'')
        Creates a packet (a byte string) from the given seq, ack, flags and chunk of data
    send_data(data, window, addr)
        Sends data to the specified address using Go-Back-N sliding window protocol.
    receive_data(addr, discard)
        Receives data from the specified address, optionally discarding specified packets.
    close_connection()
        Closes the connection with a two-way handshake.
    """


    def __init__(self, server_addr):
        """
        Constructs the sequence number, acknowledgement number, socket and server_addr
        The sequence number are set to 0, but in TCP it's a random number created by the host.

        Parameters
        ----------
        server_addr : tuple (ip, port)
            Contains the server IP and Port number in a tuple

        """
        self.seq = 0
        self.ack = 0
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.server_addr = server_addr

    def calculate_throughput(self, bytes, time_elapsed):
        """
        Calculates the throughput of the file transfer.

        Parameters
        ----------
        bytes : bytes
            The total amount of bytes received from the sender.
        time_elapsed : float
            The total amount of time elapsed during the file transfer in seconds.

        Returns
        -------
        float
            Returns the throughput in Mega bits per second in a float with 2 decimals
        """
        bits = len(bytes) * 8
        bps = bits / time_elapsed
        return round(bps / 1_000_000, 2)

    def create_packet(self, seq, ack, flags, chunk = b''):
        """
        Creates a packet to be sent over the network. Converts the integers seq, ack and flags to bytes
        using the to_bytes method, with 2 bytes each and big-endian byte order

        Parameters
        ----------
        seq : int
            The sequence number of the packet
        ack : int
            The acknowledgement number of the packet
        flags : int
            The flags of the packet
        chunk : bytes
            The payload of the packet. Default = b''

        Returns
        -------
        bytes
            The packet to be sent over the network including the header and payload/chunk
        """
        return seq.to_bytes(2, 'big') + ack.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + chunk

    def extract_header(self, packet):
        """
        Extracts and returns the header (seq, ack and flags) of a packet

        Parameters
        ---------
        packet : bytes
            The packet as a byte string

        Returns
        -------
        int, int, int
            Returns seq, ack, flags as integers
        """
        seq = int.from_bytes(packet[:2], 'big')
        ack = int.from_bytes(packet[2:4], 'big')
        flags = int.from_bytes(packet[4:6], 'big')
        return seq, ack, flags

    def send_data(self, data, window, addr):
        """
        Sends data to the specified address using Go-Back-N sliding window protocol.

        Parameters
        ----------
        data : bytes
            The chunks to be sent over the network as a byte string
        window : int
            The window size. The number of packets that the sender can send before expecting an ACK packet from the receiver
        addr : tuple
            The receiver IP and port number as a tuple
        """

        print("Start sending data:")

        # Converts the byte string of data to an array of chunks to be sent over the network
        chunks = [data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]

        # Keeps track of the number of packets currently in flight to the receiver that has not yet been ACKed
        packets_in_flight = 0

        # Keeps track of the current sliding window. Used for printing the sliding window to console
        sliding_window = deque()

        # Keep sending the chunks of data until all the data has been sent
        while self.seq <= len(chunks):

            # Send all the packets in the current sliding window
            while packets_in_flight < window and self.seq+packets_in_flight <= len(chunks):
                # Iterate over the chunks in the sliding window
                chunk = chunks[self.seq-1 + packets_in_flight]
                # Create packet to be sent with the correct sequence number
                packet = self.create_packet(self.seq+packets_in_flight, self.ack, 4, chunk)

                # Keep sending data if any unexpected exceptions that may occur when sending data over the network
                try:
                    self.sock.sendto(packet, addr)
                except Exception:
                    print(f"{datetime.now().time()} -- Error sending packet with seq = {self.seq+packets_in_flight}. Retransmitting packet")
                    continue

                # Update the sliding window
                sliding_window.append(self.seq+packets_in_flight)
                if len(sliding_window) > window: sliding_window.popleft()

                # Print packet with time, sequence number and sliding window
                print(f"{datetime.now().time()} -- packet with seq = {self.seq+packets_in_flight} sent, sliding window = {list(sliding_window)}")
                packets_in_flight += 1
            
            # When the number of packets in flight are equal to the window size,
            # start receiving ACK-packets from the receiver
            try:
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)
                # Check if the packet received is the expected ACK packet
                if flags == 4 and self.ack == seq and self.seq+1 == ack:
                    # If it is the expected ACK, then print to console, update seq and number of packets in flight
                    print(f"{datetime.now().time()} -- ACK for packet with seq = {self.seq} received")
                    self.seq = ack
                    packets_in_flight -= 1
            
            # Retransmit all the packets in the sliding window if an ACK was not received
            except timeout:
                print(f"{datetime.now().time()} -- Retransmission timeout. ACK not received.")
                packets_in_flight = 0
            except Exception as e:
                print(f"{datetime.now().time()} -- Unexpected error when receiving ACK.")
                packets_in_flight = 0
        print("Finished sending data")
    
    def receive_data(self, addr, discard):
        """
        Receives data from the specified address, optionally discarding specified packets.
        Receive data until the receiver receives a FIN packet from the sender.
        Packets that are out of order will be discarded.

        Parameters
        ----------
        addr : tuple
            The sender IP and port number as a tuple
        discard : int or None
            The sequence number of a packet that should be discarded by the receiver

        Returns
        -------
        bytes
            The payload/chunks of data that has been sent from the sender
        """

        print("Start receiving data")

        # Used for calculating the total throughput
        start_time = time.time()

        # Don't time out when receiving data. Receive data until 
        self.sock.settimeout(None)

        # The return variable holding the data
        data = b''

        # Used for calculating the total throughput
        bytes_received = b''

        # Keep receiving data until a FIN packet has been received
        while True:

            # Wait for packet from the sender and try again if any unexpected error occurs
            try:
                packet = self.sock.recvfrom(HEADER_SIZE+CHUNK_SIZE)[0]
            except Exception:
                print(f"{datetime.now().time()} -- Unexpected error when receiving data. Trying again")
                continue

            # Keep track of the total bytes received
            bytes_received += packet

            # Extract payload and header from the packet
            chunk = packet[HEADER_SIZE:]
            seq, ack, flags = self.extract_header(packet)

            # Discard packet with the given sequence number
            if seq == discard:
                discard = None
        
            # If the received packet has expected header, is in order and contains data/payload
            elif flags == 4 and self.seq == ack and self.ack == seq and chunk:
                # Try to send an ACK packet to the sender and keep receiving data if any unexpected error occurs
                try:
                    print(f"{datetime.now().time()} -- packet with seq = {seq} received")

                    # Create and send ACK packet
                    packet = self.create_packet(self.seq, self.ack+1, 4)
                    self.sock.sendto(packet, addr)
                    print(f"{datetime.now().time()} -- ACK for packet with seq = {seq} sent")

                    # Update seq number of next expected in-order packet if the ACK was sent without errors
                    self.ack += 1 
                    
                    data += chunk
                except Exception:
                    print(f"{datetime.now().time()} -- Unexpected error when sending ACK for packet with seq = {seq}. Keep receiving data")

            # If FIN packet was received
            elif flags == 6 and self.seq == ack and self.ack == seq:
                # Try to send an ACK packet to the sender and keep receiving data if any unexpected error occurs
                try:
                    # Calculate and print throughput
                    time_elapsed = time.time() - start_time
                    print(f"Throughput: {self.calculate_throughput(bytes_received, time_elapsed)} Mbps")

                    print("FIN packet received")

                    # Create and send ACK packet
                    packet = self.create_packet(self.seq, self.ack+1, 4)
                    self.sock.sendto(packet, addr)
                    print("ACK packet sent")

                    # Update seq number of next expected in-order packet if the ACK was sent without errors
                    self.ack += 1

                    print("Connection closes")
                    self.sock.close()

                    return data
                except Exception:
                    print(f"{datetime.now().time()} -- Unexpected error when sending FIN ACK packet. Keep receiving data")
            
            # Discard packet and keep receiving data if packet is out of order
            elif flags == 4:
                print(f"{datetime.now().time()} -- out-of-order packet with seq = {seq} received")
            
    
    def close_connection(self):
        """
        Closes the connection with a two-way handshake.
        Sends a FIN packet to the receiver and closes the connection if
        the receiver returns an ACK packet.
        """

        print("Connection teardown. Two way handshake")
        
        # Keep sending until an ACK packet has been returned
        while True:
            try:
                # Create and send FIN packet
                packet = self.create_packet(self.seq, self.ack, 6)
                self.sock.sendto(packet, self.server_addr)
                print("FIN packet sent")     
                # Receive packet and extract header
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)
                # Check if it's the expected ACK packet
                if flags == 4 and ack == self.seq+1 and self.ack == seq:
                    print("ACK packet received")
                    self.seq = ack
                    print("Connection closes")
                    self.sock.close()
                    break
            # Resend FIN packet if no ACK packet was received
            # Raise an exception if any other error occurs,
            # for example if the receiver receives the FIN, but the returned ACK was lost
            except timeout:
                print("ACK not received in time. Resending FIN packet")   
            except Exception as e:
                print(f"Unexpected error occurred during connection teardown")
                raise
