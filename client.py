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
            try:
                self.sock.sendto(packet, self.server_addr)
                print("SYN packet sent")
                packet = self.sock.recvfrom(HEADER_SIZE)[0]
                seq, ack, flags = self.extract_header(packet)
                if flags == 12 and ack == self.seq+1:
                    print("SYN-ACK packet received")
                    self.ack, self.seq = seq+1, ack
                    packet = self.create_packet(self.seq, self.ack, 4)
                    self.sock.sendto(packet, self.server_addr)
                    print("ACK packet sent")
                    break
            except timeout:    
                print("Connection failed. SYN-ACK not received in time.")
                raise
                    
            except Exception as e:
                print(f"Connection failed. Error occurred during three way handshake: {e}")
                raise
