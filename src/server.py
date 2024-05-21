from host import *

class Server(Host):
    """
    This class represents the server host. It is a subclass of Host.

    Attributes
    ----------
    client_addr : tuple (ip, port)
        This attribute holds the client IP and port number as a tuple

    Methods
    -------
    """
    def __init__(self, server_addr):
        """
        Calls the constuctor of the Host class, declares the client_addr variable and binds the server socket
        """
        super().__init__(server_addr)
        self.client_addr = None
        try:
            self.sock.bind(server_addr)
        except Exception:
            print(f"Error while binding server socket")
            raise
    
    def listen(self):
        """
        Wait for the client to send a SYN packet and initiate a three way handshake

        Raises
        ------
        Exception
            Raises exception if any error occurs while receiving SYN from client
        """
        # Receive packets until the packet received is a SYN packet
        while True:
            try:
                packet, self.client_addr = self.sock.recvfrom(HEADER_SIZE)
                self.ack, _, flags = self.extract_header(packet)
                # Return if the received packet is a SYN packet
                if flags == 8:
                    self.ack += 1
                    print("SYN packet received")
                    return
            except Exception:
                print(f"Error occurred while waiting for connection from client")
                raise
    
    def accept(self):
        """
        Continues three way handshake by sending a SYN-ACK to client and waiting for a returned ACK

        Returns
        -------
        tuple (ip, port)
            Returns the client IP and port number as a tuple

        Raises
        ------
        Exception
            Raises an exception if any errors occurs during sending or receiving
        """
        # Sets timeout value. sock.recvfrom() will raise a timeout exception if it doesn't receive
        # anything within the time limit
        self.sock.settimeout(TIMEOUT)

        # Keep sending SYN-ACK packets until an ACK-packet is received
        while True:
            try:
                # Create and send SYN-ACK
                packet = self.create_packet(self.seq, self.ack, 12)
                self.sock.sendto(packet, self.client_addr)
                print("SYN-ACK packet sent")

                # Wait for ACK from client
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)

                # Check if received packet is an ACK packet
                if flags == 4 and ack == self.seq+1 and self.ack == seq:
                    print("ACK packet received")
                    print("Connection established")
                    self.seq = ack
                    return self.client_addr
            # Keep sending SYN-ACKs if timeout occurs
            except timeout:
                print("ACK packet not received in time.")
            # Raise an exception if any other errors occurs during sending or receiving
            except Exception:
                print(f"Connection failed. Error occurred during three way handshake")
                raise
            