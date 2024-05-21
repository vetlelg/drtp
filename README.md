# Reliable File Transfer Application over UDP

## Introduction

This project implements a reliable file transfer application using UDP as the underlying transport protocol. Despite UDP's inherent lack of reliability and connection management, this application ensures reliable data transmission by implementing a custom protocol on top of UDP. The key features include a three-way handshake for connection establishment, a Go-Back-N sliding window protocol for data transmission, and a two-way handshake for connection teardown.

## Features

- Three-way handshake for connection establishment
- Go-Back-N sliding window protocol for reliable data transmission
- Two-way handshake for connection termination
- Command-line interface for easy configuration

### Usage

The application can be run in either server mode or client mode. Below are the instructions for both modes.

#### Server Mode

To start the server, use the `-s` or `--server` flag along with the required parameters.

```bash
python application.py --server --port 8088 --ip 127.0.0.1 --file received_file.txt
```

- `--server`: Enable server mode
- `--port`: Specify the server port number (default: 8088)
- `--ip`: Specify the server IP address (default: 127.0.0.1)
- `--file`: Specify the filename to save the received data

Optionally, you can use the `--discard` flag to specify a sequence number of a packet to be discarded by the server for testing retransmission.

```bash
python application.py --server --port 8088 --ip 127.0.0.1 --file received_file.txt --discard 5
```

#### Client Mode

To start the client, use the `-c` or `--client` flag along with the required parameters.

```bash
python application.py --client --port 8088 --ip 127.0.0.1 --file send_file.txt --window 3
```

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

- `application.py`: Entry point of the application, handles argument parsing and orchestrates server/client operations.
- `host.py`: Defines the `Host` base class containing common functionalities for both client and server.
- `client.py`: Implements the `Client` class for client-specific operations.
- `server.py`: Implements the `Server` class for server-specific operations.