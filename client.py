from host import *

class Client(Host):
    """
    This class represents the client host. It is a subclass of Host.

    Methods
    -------
    connect()
        Establishes a connection with the server.
        Initiates a three way handshake by sending a SYN packet to server and receiving a SYN-ACK packet from the server.
        If the SYN-ACK is not received in time or any other errors occur the connection fails.
    """
    def __init__(self, server_addr):
        """
        Calls the constructor of the Host class and sets the timeout value
        """
        super().__init__(server_addr)
        # Sets the timeout value
        self.sock.settimeout(TIMEOUT)
    
    def connect(self):
        """
        Establishes a connection with the server.
        Initiates a three way handshake by sending a SYN packet to server and receiving a SYN-ACK packet from the server.
        If the SYN-ACK is not received in time or any other errors occur the connection fails.

        Raises
        ------
        TimeoutError
            Raises a timeout error if the SYN-ACK is not received within TIMEOUT
        Exception
            Raises an exception if any errors occurs that may occur when sending or receiving data on the network
        """

        print("Establishing connection. Three way handshake")
        while True:
            try:
                # Create and send SYN packet
                packet = self.create_packet(self.seq, self.ack, 8)
                self.sock.sendto(packet, self.server_addr)
                print("SYN packet sent")

                # Receive packet and extract header
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)

                # Return ACK if the received packet is the expected SYN-ACK packet
                if flags == 12 and ack == self.seq+1:
                    print("SYN-ACK packet received")
                    self.ack, self.seq = seq+1, ack
                    packet = self.create_packet(self.seq, self.ack, 4)
                    self.sock.sendto(packet, self.server_addr)
                    print("ACK packet sent")
                    break
            # Return and raise an exception if SYN-ACK packet was not received in time or any other error occurs
            except timeout:    
                print("Connection failed. SYN-ACK not received in time.")
                raise
            except Exception:
                print(f"Connection failed. Error occurred during three way handshake.")
                raise
