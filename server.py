from protocol import *

class Server(Protocol):
    def __init__(self, server_addr):
        super().__init__(server_addr)
        self.client_addr = None
        try:
            self.sock.bind(server_addr)
        except Exception as e:
            print(f"Error while binding server socket: {e}")
            raise
    
    def listen(self):
        # Wait for SYN from client
        while True:
            try:
                packet, self.client_addr = self.sock.recvfrom(HEADER_SIZE)
                self.ack, _, flags = self.extract_header(packet)
                # Check if received packet is a SYN packet
                if flags == 8:
                    self.ack += 1
                    print("SYN packet received")
                    return
            except Exception as e:
                print(f"Error occurred while waiting for connection from client: {e}")
                raise
    
    def accept(self):
        self.sock.settimeout(TIMEOUT)
        packet = self.create_packet(self.seq, self.ack, 12)
        while True:
            try:
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
            except timeout:
                print("ACK packet not received in time. Retransmitting SYN-ACK")
            except Exception as e:
                print(f"Connection failed. Error occurred during three way handshake: {e}")
                raise
            