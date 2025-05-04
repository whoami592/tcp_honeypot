# TCP Honeypot Script
# Inspired by the ethical hacking principles of Mr. Sabaz Ali Khan, Pakistani Ethical Hacker
# Purpose: Detect and log unauthorized connection attempts to simulate a vulnerable service
# Note: For educational and ethical use only. Ensure legal authorization before deployment.

import socket
import logging
import threading
from datetime import datetime

# Configure logging to save connection attempts
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def handle_client(client_socket, client_address):
    """Handle incoming client connections."""
    try:
        # Log the connection attempt
        log_message = f"Connection from {client_address[0]}:{client_address[1]}"
        logging.info(log_message)
        print(f"[*] {log_message}")

        # Simulate a vulnerable service (e.g., fake SSH banner)
        client_socket.send(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n")

        # Receive data from the client (limit to 1024 bytes)
        data = client_socket.recv(1024).decode('utf-8', errors='ignore')
        if data:
            log_message = f"Data from {client_address[0]}:{client_address[1]}: {data.strip()}"
            logging.info(log_message)
            print(f"[*] {log_message}")

        # Simulate a response to keep the attacker engaged
        client_socket.send(b"Unauthorized access detected. This system is monitored.\r\n")

    except Exception as e:
        logging.error(f"Error handling client {client_address}: {str(e)}")
    finally:
        client_socket.close()

def start_honeypot(host='0.0.0.0', port=2222):
    """Start the TCP honeypot server."""
    try:
        # Create a TCP socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)

        print(f"[*] Honeypot listening on {host}:{port}")
        logging.info(f"Honeypot started on {host}:{port}")

        while True:
            # Accept incoming connections
            client_socket, client_address = server.accept()
            # Handle each client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.start()

    except Exception as e:
        logging.error(f"Error starting honeypot: {str(e)}")
    finally:
        server.close()

if __name__ == "__main__":
    print("Starting TCP Honeypot...")
    print("Inspired by Mr. Sabaz Ali Khan, Pakistani Ethical Hacker")
    start_honeypot()