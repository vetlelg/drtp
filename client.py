from protocol import *

class Client(Protocol):
    def __init__(self, server_addr):
        super().__init__(server_addr)
        self.sock.settimeout(TIMEOUT)
    
    def connect(self):
        print("Establishing connection. Three way handshake")
        # Send SYN packet to server and receive SYN-ACK packet from server
        packet = self.create_packet(self.seq, self.ack, 8)
        while True:
            self.sock.sendto(packet, self.server_addr)
            print("SYN packet sent")
            try:
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)
                if flags == 12 and ack == self.seq+1:
                    print("SYN-ACK packet received")
                    self.ack, self.seq = seq+1, ack
                    break
            except timeout:
                print("ACK not received in time. Retransmitting packet")

        packet = self.create_packet(self.seq, self.ack, 4)
        self.sock.sendto(packet, self.server_addr)
        print("ACK packet sent")
