import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, ParameterFormat,
    load_pem_parameters, load_pem_public_key
)

HOST = '10.0.0.217'  # MODIFY #
PORT = 65432

class SecureChatClient:
    def __init__(self):
        self.socket = None
        self.running = False
        self.username = None
        self.aes_key = None

    def derive_aes_key(self, shared_secret):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-chat-key',
        ).derive(shared_secret)

    def encrypt_message(self, message):
        """Encrypts string to bytes using AES-GCM"""
        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(nonce),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag

    def decrypt_message(self, encrypted_data):
        """Decrypts bytes to string using AES-GCM"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.GCM(nonce, tag),
        )
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

    def perform_key_exchange(self):
        try:
            # 1. Receive DH parameters for key exchange
            params_len = int.from_bytes(self.socket.recv(4), 'big')
            params_bytes = self.socket.recv(params_len)
            dh_parameters = load_pem_parameters(params_bytes)
            
            # 2. Receive server public key
            server_pub_len = int.from_bytes(self.socket.recv(4), 'big')
            server_pub_bytes = self.socket.recv(server_pub_len)
            server_pub_key = load_pem_public_key(server_pub_bytes)
            
            # 3. Generate and send client public key
            client_priv_key = dh_parameters.generate_private_key()
            client_pub_bytes = client_priv_key.public_key().public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo
            )
            self.socket.sendall(len(client_pub_bytes).to_bytes(4, 'big'))
            self.socket.sendall(client_pub_bytes)
            
            # 4. Derive shared secret
            shared_secret = client_priv_key.exchange(server_pub_key)
            self.aes_key = self.derive_aes_key(shared_secret)
            print(f"[DEBUG] Derived AES key: {self.aes_key.hex()}")
            return True
            
        except Exception as e:
            print(f"Key exchange failed: {e}")
            return False

    def send_encrypted(self, message):
        """Encrypts and sends a string message"""
        encrypted = self.encrypt_message(message)
        self.socket.sendall(len(encrypted).to_bytes(4, 'big'))
        self.socket.sendall(encrypted)

    def receive_encrypted(self):
        """Receives and decrypts a message to string"""
        try:
            length_bytes = self.socket.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                return None
            length = int.from_bytes(length_bytes, 'big')
            encrypted = b''
            while len(encrypted) < length:
                chunk = self.socket.recv(length - len(encrypted))
                if not chunk:
                    return None
                encrypted += chunk
            return self.decrypt_message(encrypted) if encrypted else None
        except Exception as e:
            print(f"Receive error: {e}")
            return None

    def auth(self):
        try:
            if not self.perform_key_exchange():
                return False

            while True:
                username = input("Enter your username: ").strip()
                if not username:
                    print("Username cannot be empty")
                    continue
                
                # Send encrypted username
                self.send_encrypted(username)
                
                # Get response
                response = self.receive_encrypted()
                if response == "Enter password: ":
                    password = input("Enter your password: ").strip()
                    self.send_encrypted(password)
                    
                    auth_result = self.receive_encrypted()
                    if auth_result == "AUTHENTICATED":
                        print(f"Welcome {username}!")
                        self.username = username
                        return True
                
                print("Authentication failed. Try again.")
                
        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            print(f"Connected to {HOST}:{PORT}")
            
            if not self.auth():
                return
                
            self.running = True
            threading.Thread(target=self.listener, daemon=True).start()
            
            # Main chat loop
            while self.running:
                message = input().strip()
                if not message:
                    continue
                
                if message.lower() == 'exit':
                    self.send_encrypted(message)
                    break
                    
                self.send_encrypted(message)
                
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            print("Disconnected")

    def listener(self):
        while self.running:
            try:
                message = self.receive_encrypted()
                if not message:
                    break
                if not message.startswith(f"{self.username}: "):
                    print(f"\n{message}\nYou: ", end="", flush=True)
            except Exception as e:
                print(f"\nReceive error: {e}")
                break

if __name__ == "__main__":
    client = SecureChatClient()
    client.start()
