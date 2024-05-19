from protocol import *

class Server(Protocol):
    def __init__(self, server_addr):
        super().__init__(server_addr)
        self.client_addr = None
        self.sock.bind(server_addr)
    
    def listen(self):
        # Wait for SYN from client
        while True:
            packet, self.client_addr = self.sock.recvfrom(HEADER_SIZE)
            self.ack, _, flags = self.extract_header(packet)
            self.ack += 1
            # Check if received packet is a SYN packet
            if flags == 8:
                print("SYN packet received")
                break
    
    def accept(self):
        self.sock.settimeout(TIMEOUT)
        packet = self.create_packet(self.seq, self.ack, 12)
        while True:
            self.sock.sendto(packet, self.client_addr)
            print("SYN-ACK packet sent")
            try:
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
                print("Timeout. ACK packet not received.")
            