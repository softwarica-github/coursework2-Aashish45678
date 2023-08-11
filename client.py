

import socket
import threading
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, END
import hashlib
import sqlite3



def create_table():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL)''')
    conn.commit()
    conn.close()



def hash_password(password):
    # Use SHA-256 to hash the password
    hash_obj = hashlib.sha256(password.encode())
    return hash_obj.hexdigest()

def insert_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

def login_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cursor.fetchone()
    conn.close()
    return user



def signup():
    username = input("Enter a username: ")
    password = input("Enter a password: ")

    if not username or not password:
        print("Username and password cannot be empty.")
        return

    try:
        insert_user(username, password)
        print("Account created successfully.")
    except sqlite3.IntegrityError:
        print("Username already exists. Please choose a different one.")
    except Exception as e:
        print(f"Error occurred during signup: {e}")


def login():
    global username, password
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if not username or not password:
        print("Username and password cannot be empty.")
        return False

    try:
        user = login_user(username, password)
        if user:
            print("Login successful.")
            return True
        else:
            print("Invalid username or password.")
            return False
    except Exception as e:
        print(f"Error occurred during login: {e}")
        return False

    

def main():
    create_table()

    login_successful = False

    while not login_successful:
        choice = input("Choose an option (1: Signup, 2: Login): ")

        if choice == "1":
            signup()
        elif choice == "2":
            login_successful = login()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")

# Set up the GUI
root = tk.Tk()
root.title("Simple Chat Client")
root.geometry("1350x800")

# Server's IP address and port
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002
separator_token = "<SEP>"

# Define a secret key for encryption
SECRET_KEY = b'MySecretKey123'  # Replace this with your own secret key

# Initialize TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((SERVER_HOST, SERVER_PORT))

# Receive the server's prompt to enter the name and password
server_prompt = s.recv(1024).decode()

# Prompt the client for a name
client_name = simpledialog.askstring("Nickname", server_prompt)


# Send the name and password to the server
credentials = f"{client_name}"
s.send(credentials.encode())


# Function for XOR encryption
def xor_encrypt(text):
    encrypted_text = bytes([text[i] ^ SECRET_KEY[i % len(SECRET_KEY)] for i in range(len(text))])
    return encrypted_text

# Function for XOR decryption
def xor_decrypt(encrypted_text):
    decrypted_text = bytes([encrypted_text[i] ^ SECRET_KEY[i % len(SECRET_KEY)] for i in range(len(encrypted_text))])
    return decrypted_text

# Function to receive messages from the server
def receive_messages():
    while True:
        try:
            message = s.recv(1024)
            if not message:
                print("Disconnected from the server.")
                break
            if message.startswith(b"[CLIENTS]"):
                # Update the list of connected clients in the Listbox
                clients = message.split(separator_token.encode())[1:]
                root.after(100, update_client_list, clients)
            else:
                # Decrypt the incoming message before displaying it
                decrypted_message = xor_decrypt(message).decode()
                msg_box.insert(tk.END, decrypted_message + '\n')
        except Exception as e:
            print(f"[!] Error: {e}")
            break

# Start the thread to receive messages
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

# Function to send messages to the server
def send_message():
    to_send = entry.get()
    date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Encrypt the message with sender's name and separator token before sending it
    to_encrypt = f"[{date_now}] {client_name}{separator_token}{to_send}"
    encrypted_message = xor_encrypt(to_encrypt.encode())

    s.send(encrypted_message)

    # Add the sent message to the message box
    msg_box.insert(tk.END, f"[{date_now}] You: {to_send}\n")


    entry.delete(0, tk.END)

# Function to update the client list in the Listbox
def update_client_list(clients):
    client_list.delete(0, END)
    for client in clients:
        client_list.insert(tk.END, client.decode()+"\n",)


# Heading
heading_label = tk.Label(root, text="Simple Chat Client", font=("Helvetica", 20, "bold"))
heading_label.grid(row=0, column=0, columnspan=3, pady=10)

# Message Box Heading (Chat Room Name)
chat_room_name = "My Awesome Chat Room"  # Replace this with the desired chat room name
msg_box_heading = tk.Label(root, text=f"Chat Room: {chat_room_name}", font=("Helvetica", 16, "bold"))
msg_box_heading.grid(row=1, column=0, columnspan=3, pady=10)


user_label= tk.Label(root, text=f"Username: {username}", font=("Helvetica", 14, "bold"), fg="blue")
user_label.grid(row=2, column=0, pady=10)


status_label= tk.Label(root, text="Status: Online", font=("Helvetica", 14, "bold"), fg="green")
status_label.grid(row=2, column=2, pady=10)


# Listbox to display connected clients
client_list = tk.Listbox(root, height=20, width=20, font=("Helvetica", 12))
client_list.grid(row=4, column=0, padx=10, pady=10, rowspan=2)


# Messages Box
msg_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=15, width=60, font=("Helvetica", 12))
msg_box.grid(row=4, column=1, padx=10, pady=10, rowspan=2)


# Placeholder Text in Message Entry
entry = tk.Entry(root, width=60, font=("Helvetica", 12))
entry.insert(tk.END, "Write your message here !!!")
entry.grid(row=6, column=1, padx=15, pady=5, columnspan=2)

# Send Button
send_button = tk.Button(root, text="Send", command=send_message)
send_button.grid(row=6, column=2, pady=5)

# Function to close the socket before closing the GUI
def on_close():
    try:
        s.close()
    except Exception as e:
        print(f"Error occurred while closing socket: {e}")
    root.destroy()


def show_message_box(title, message):
    messagebox.showinfo(title, message)    

root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()
