
import socket
import logging
from threading import Thread
import tkinter as tk
from tkinter import scrolledtext

# Server's IP address
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002  # Port we want to use
separator_token = "<SEP>"  # We will use this to separate the client name & message

# Username and Password for authentication
REQUIRED_USERNAME = "admin"
REQUIRED_PASSWORD = "password123"

# Define a secret key for encryption
SECRET_KEY = b'MySecretKey123'  # Replace this with your own secret key

# Set up logging configuration
logging.basicConfig(filename='server_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')


# Initialize list/set of all connected client's sockets and names
client_sockets = set()
client_names = {}

# Create a TCP socket
s = socket.socket()
# Make the port as a reusable port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Bind the socket to the address we specified
s.bind((SERVER_HOST, SERVER_PORT))
# Listen for upcoming connections
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
logging.info(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")


def display_log_message(message):
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)


# Function for XOR encryption
def xor_encrypt(text):
    try:
        encrypted_text = ''.join(chr(ord(text[i]) ^ SECRET_KEY[i % len(SECRET_KEY)]) for i in range(len(text)))
        return encrypted_text
    except Exception as e:
        logging.error(f"[!] Error during encryption: {e}")
        return ""

# Function for XOR decryption
def xor_decrypt(encrypted_text):
    try:
        decrypted_text = ''.join(chr(ord(encrypted_text[i]) ^ SECRET_KEY[i % len(SECRET_KEY)]) for i in range(len(encrypted_text)))
        return decrypted_text
    except Exception as e:
        logging.error(f"[!] Error during decryption: {e}")
        return ""
    

def handle_client_messages(cs, client_name):
    while True:
        try:
            msg = cs.recv(1024).decode()
            if not msg:  # If the received message is empty, the client disconnected
                raise ConnectionResetError("Client disconnected.")  # Trigger ConnectionResetError

            # Log the received encrypted message
            logging.info(f"[Received from {client_name}] {msg}")

            # Decrypt the incoming message before processing
            decrypted_message = xor_decrypt(msg)
            decrypted_message = decrypted_message.replace(separator_token, ": ")

            # Broadcast the decrypted message to all other clients
            for client_socket in client_sockets.copy():  # Use a copy to avoid modifying set while iterating
                try:
                    if client_socket is not cs:  # Avoid sending the message back to the sender
                        # Encrypt the message before sending it
                        encrypted_message = xor_encrypt(decrypted_message)
                        client_socket.send(encrypted_message.encode())

                        # Log the sent encrypted message
                        logging.info(f"[Sent to {client_names[client_socket]}] {encrypted_message}")
                except Exception as e:
                    print(f"[!] Error: {e}")
                    logging.error(f"[!] Error: {e}")
                    client_socket.close()
                    client_sockets.remove(client_socket)
                    del client_names[client_socket]
                    broadcast_connected_clients()
                    break
        except ConnectionResetError as e:
            print(f"[-] {client_name} disconnected.")
            logging.info(f"[-] {client_name} disconnected.")
            display_log_message(f"[-] {client_name} disconnected.")
            cs.close()
            client_sockets.remove(cs)
            del client_names[cs]
            broadcast_connected_clients()
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            logging.error(f"[!] Error: {e}")
            cs.close()
            client_sockets.remove(cs)
            del client_names[cs]
            broadcast_connected_clients()
            break


def broadcast_connected_clients():
    connected_clients = "[CLIENTS]" + separator_token + " ".join(list(client_names.values()))
    for client_socket in client_sockets:
        try:
            client_socket.send(connected_clients.encode())
        except Exception as e:
            print(f"[!] Error: {e}")
            logging.error(f"[!] Error: {e}")
            client_socket.close()
            client_sockets.remove(client_socket)
            del client_names[client_socket]
            broadcast_connected_clients()
            break


def accept_client_connections():
    while True:
        try:
            # We keep listening for new connections all the time
            client_socket, client_address = s.accept()
            # Prompt the client for a name
            client_socket.send("Enter your Nickname: ".encode())
            client_name = client_socket.recv(1024).decode()
            print(f"[+] {client_name} ({client_address}) connected.")
            logging.info(f"[+] {client_name} ({client_address}) connected.")
            display_log_message(f"[+] {client_name} ({client_address}) connected.")
            # Add the new connected client to connected sockets and store its name
            client_sockets.add(client_socket)
            client_names[client_socket] = client_name
            # Send the updated client list to the newly connected client
            send_client_list_on_connect(client_socket)
            # Start a new thread that listens for each client's messages
            t = Thread(target=handle_client_messages, args=(client_socket, client_name))
            # Make the thread daemon so it ends whenever the main thread ends
            t.daemon = True
            # Start the thread
            t.start()
            # Send the updated client list to all clients
            broadcast_connected_clients()
        except Exception as e:
            print(f"[!] Error: {e}")
            logging.error(f"[!] Error: {e}")
            break

def send_client_list_on_connect(client_socket):
    connected_clients = "[CLIENTS]" + separator_token + " ".join(list(client_names.values()))
    client_socket.send(connected_clients.encode())

# Create the main window
root = tk.Tk()
root.title("Chat Server")

# Host and Port information
host_label = tk.Label(root, text=f"Host: {SERVER_HOST}", font=("Arial", 12, "bold"))
port_label = tk.Label(root, text=f"Port: {SERVER_PORT}", font=("Arial", 12, "bold"))
client_details_label = tk.Label(root, text="*****************************Client Connection Details*****************************", font=("Arial", 12, "bold"))

host_label.pack(pady=5)
port_label.pack(pady=5)
client_details_label.pack(pady=5)

# ScrolledText widget to display log messages
log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=15)
log_text.pack(padx=10, pady=10)


def close_server():
    for cs in client_sockets:
        try:
            cs.close()
        except Exception as e:
            logging.error(f"[!] Error while closing client socket: {e}")
    try:
        s.close()
    except Exception as e:
        logging.error(f"[!] Error while closing server socket: {e}")
    root.destroy()


close_button = tk.Button(root, text="Close Server", command=close_server)
close_button.pack(pady=10)

accept_thread = Thread(target=accept_client_connections)
accept_thread.daemon = True
accept_thread.start()

root.mainloop()
