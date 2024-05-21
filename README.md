# DATA2410 Reliable Transport Protocol (DRTP)

## Introduction

This project implements DATA2410 reliable transport protocol (DRTP) on top of the User Datagram Protocol (UDP) to create a simple reliable file transfer application in Python. The functionalities of the project include a three-way handshake for connection establishment, Go-Back-N sliding window protocol for data transmission and a two-way handshake for connection teardown. The application reads a file from the client, sends it over the network to the server and writes it to a file on the server. 

### Usage

The application can be run in either server mode or client mode. Below are the instructions for both modes.

#### Server Mode

- `--server`: Enable server mode
- `--port`: Specify the server port number (default: 8088)
- `--ip`: Specify the server IP address (default: 127.0.0.1)
- `--file`: Specify the filename to save the received data

Optionally, you can use the `--discard` flag to specify a sequence number of a packet to be discarded by the server for testing retransmission.

```bash
python application.py --server --port 8088 --ip 127.0.0.1 --file received_file.txt --discard 5
```

#### Client Mode

- `--client`: Enable client mode
- `--port`: Specify the server port number (default: 8088)
- `--ip`: Specify the server IP address (default: 127.0.0.1)
- `--file`: Specify the filename to be sent
- `--window`: Set the sliding window size (default: 3)

### Example

1. Start the server on one terminal:

   ```bash
   python application.py --server --port 8088 --ip 127.0.0.1 --file received_file.txt
   ```

2. Start the client on another terminal:

   ```bash
   python application.py --client --port 8088 --ip 127.0.0.1 --file send_file.txt --window 3
   ```

3. The client will send the file `send_file.txt` to the server, which will save it as `received_file.txt`.

## Code Structure

- `application.py`: This includes the main function and uses the argparse library to parse command-line arguments to determine the sliding window size, file path/name, server IP-address, server port number and whether the application should run in server- or client-mode.
- `host.py`: This file contains the Host class which is used as a base class for the server and the client. It includes key functionality like packet creation, header extraction, sending of data using the Go-Back-N protocol and connection teardown.
- `client.py`: Thise file contains the Client class which inherits from the Host class and holds client-specific functionality like initiation the three-way handshake (Sending of SYN and receiving of SYN-ACK)
- `server.py`: The Server class also inherits from the Host class and implements server-specific functions. It listens for incoming client-connections (SYN-packets) and completes the connection establishment with the client (Sending SYN-ACK and receiving ACK)