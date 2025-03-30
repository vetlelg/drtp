import pytest
from src.host import Host, HEADER_SIZE
import math

def test_create_and_extract_packet():
    """
    Test that create_packet and extract_header produce/consume
    a packet's header (seq, ack, flags) and payload consistently.
    """
    host = Host(('127.0.0.1', 8088))
    
    seq = 1
    ack = 2
    flags = 4
    payload = b'Hello, DRTP!'

    packet = host.create_packet(seq, ack, flags, payload)
    
    # Ensure packet length = HEADER_SIZE + len(payload)
    assert len(packet) == HEADER_SIZE + len(payload)
    
    # Extract header again
    extracted_seq, extracted_ack, extracted_flags = host.extract_header(packet)
    
    assert extracted_seq == seq
    assert extracted_ack == ack
    assert extracted_flags == flags
    
    # Extract the payload
    extracted_payload = packet[HEADER_SIZE:]
    assert extracted_payload == payload


def test_calculate_throughput():
    """
    Test that calculate_throughput returns the correct Mbps value.
    """
    host = Host(('127.0.0.1', 8088))
    
    # Suppose we transferred 1,000,000 bytes in 1 second
    bytes_transferred = b'a' * 1_000_000
    time_elapsed = 1.0
    
    throughput = host.calculate_throughput(bytes_transferred, time_elapsed)
    
    # 1,000,000 bytes = 8,000,000 bits = 8 Mbps
    # Our function returns throughput in Mbps, with 2 decimals
    
    # We check float values with math.isclose to avoid floating point precision issues
    assert math.isclose(throughput, 8.00, rel_tol=1e-9, abs_tol=1e-9)



def test_host_initialization():
    """
    Test that the Host class initializes the sequence and ack numbers to 0,
    and stores the given server address properly.
    """
    server_addr = ('127.0.0.1', 8088)
    host = Host(server_addr)
    
    assert host.seq == 0
    assert host.ack == 0
    assert host.server_addr == server_addr
    assert host.sock is not None
