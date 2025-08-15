import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, ParameterFormat,
    load_pem_public_key
)

HOST = '10.0.0.217'  # Modify #
PORT = 65432

class SecureChatServer:
    def __init__(self):
        self.online_users = {}  # {socket: (username, aes_key)}
        self.users = {"bobb": "123", "alice": "123"}  # Plaintext storage for simplicity
        self.lock = threading.Lock()

        # Pre-generate DH parameters for key exchange
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.dh_params_pem = self.dh_parameters.parameter_bytes(
            Encoding.PEM,
            ParameterFormat.PKCS3
        )

    def derive_aes_key(self, shared_secret):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-chat-key',
        ).derive(shared_secret)

    def encrypt_message(self, key, message):
        """Encrypts string to bytes using AES-GCM"""
        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag

    def decrypt_message(self, key, encrypted_data):
        """Decrypts bytes to string using AES-GCM"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
        )
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

    def send_encrypted(self, conn, key, message):
        """Encrypts and sends a string message"""
        encrypted = self.encrypt_message(key, message)
        conn.sendall(len(encrypted).to_bytes(4, 'big'))
        conn.sendall(encrypted)

    def receive_encrypted(self, conn, key):
        """Receives and decrypts a message to string"""
        try:
            length_bytes = conn.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                return None
            length = int.from_bytes(length_bytes, 'big')
            encrypted = b''
            while len(encrypted) < length:
                chunk = conn.recv(length - len(encrypted))
                if not chunk:
                    return None
                encrypted += chunk
            return self.decrypt_message(key, encrypted) if encrypted else None
        except Exception as e:
            print(f"Receive error: {e}")
            return None

    def perform_key_exchange(self, conn):
        try:
            # 1. Send DH parameters
            conn.sendall(len(self.dh_params_pem).to_bytes(4, 'big'))
            conn.sendall(self.dh_params_pem)
            
            # 2. Generate and send server public key
            server_priv_key = self.dh_parameters.generate_private_key()
            server_pub_pem = server_priv_key.public_key().public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(len(server_pub_pem).to_bytes(4, 'big'))
            conn.sendall(server_pub_pem)
            
            # 3. Receive client_public key
            client_pub_len = int.from_bytes(conn.recv(4), 'big')
            client_pub_pem = conn.recv(client_pub_len)
            client_pub_key = load_pem_public_key(client_pub_pem)
            
            # 4. Derive shared_secret
            shared_secret = server_priv_key.exchange(client_pub_key)
            aes_key = self.derive_aes_key(shared_secret)
            print(f"[DEBUG] Derived AES key: {aes_key.hex()}")
            return aes_key
            
        except Exception as e:
            print(f"Key exchange failed: {e}")
            return None

    def authenticate_client(self, conn, aes_key):
        try:
            # 1. Get username
            username = self.receive_encrypted(conn, aes_key)
            if not username or username not in self.users:
                self.send_encrypted(conn, aes_key, "AUTH_FAIL")
                return None
                
            # 2. Request password
            self.send_encrypted(conn, aes_key, "Enter password: ")
            
            # 3. Verify password
            password = self.receive_encrypted(conn, aes_key)
            if password == self.users[username]:
                self.send_encrypted(conn, aes_key, "AUTHENTICATED")
                return username
                
            self.send_encrypted(conn, aes_key, "AUTH_FAIL")
            return None
            
        except Exception as e:
            print(f"Authentication error: {e}")
            return None

    def broadcast(self, sender_conn, message, sender_aes_key):
        """Send message to all clients except sender"""
        with self.lock:
            # The client's unique AES key is required to encrypt the message for that client
            sender_username = self.online_users.get(sender_conn, (None, None))[0]
            if not sender_username: return
            formatted_message = f"{sender_username}: {message}"
            
            for conn, (user, key) in self.online_users.items():
                if conn != sender_conn:
                    try:
                        self.send_encrypted(conn, key, formatted_message)
                    except Exception as e:
                        print(f"Failed to send to {user}: {e}")
                        # Remove disconnected clients
                        pass

    def handle_client(self, conn, addr):
        aes_key = None
        username = None
        try:
            # 1. Perform key exchange
            aes_key = self.perform_key_exchange(conn)
            if not aes_key:
                return
                
            # 2. Authenticate
            username = self.authenticate_client(conn, aes_key)
            if not username:
                return
                
            # 3. Add to online users
            with self.lock:
                self.online_users[conn] = (username, aes_key)
            print(f"User {username} connected from {addr}")
            
            # 4. Main message loop
            while True:
                message = self.receive_encrypted(conn, aes_key)
                if not message or message.lower() == 'exit':
                    break
                    
                print(f"{username}: {message}")
                self.broadcast(conn, message, aes_key)
                
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            with self.lock:
                if conn in self.online_users:
                    del self.online_users[conn]
            conn.close()
            print(f"Disconnected: {addr}")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            print(f"Server listening on {HOST}:{PORT}")
            s.listen()
            
            while True:
                conn, addr = s.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                ).start()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
