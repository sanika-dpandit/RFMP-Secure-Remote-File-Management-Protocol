import socket
import subprocess
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import base64
import os
from datetime import datetime

# Caesar Cipher class
class CaesarCipher:
    @staticmethod
    def encrypt(text, shift):
        return ''.join(
            chr((ord(char) - 32 + shift) % 95 + 32) if 32 <= ord(char) <= 126 else char
            for char in text
        )

    @staticmethod
    def decrypt(text, shift):
        return ''.join(
            chr((ord(char) - 32 - shift) % 95 + 32) if 32 <= ord(char) <= 126 else char
            for char in text
        )

# Encryptor class for AES and session key management
class Encryptor:
    @staticmethod
    def aes_encrypt(key, data):
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = b""
        # Process the data in 16-byte chunks
        while len(data) > 0:
            chunk = data[:16]
            if len(chunk) == 16:
                ciphertext += cipher.encrypt(chunk.encode('utf-8'))
            data = data[16:]  # Remove the processed chunk
        return base64.b64encode(ciphertext).decode()  # Return the base64 encoded ciphertext

    @staticmethod
    def aes_decrypt(key, data):
        data = base64.b64decode(data)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = b""
        # Decrypt the data in 16-byte chunks
        while len(data) > 0:
            chunk = data[:16]
            decrypted_data += cipher.decrypt(chunk)
            data = data[16:]  # Remove the processed chunk
        return decrypted_data.decode('utf-8')

class ServerThread(threading.Thread):
    def __init__(self, client_socket, client_address, server_private_key, server_public_key):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.server_private_key = server_private_key
        self.server_public_key = server_public_key
        self.session_key = None
        self.cipher_type = None
        self.caesar_shift = 3  # Default Caesar cipher shift

    def send_response(self, response_type, message):
        if self.cipher_type == "AES" and self.session_key:
            message = Encryptor.aes_encrypt(self.session_key, message)
        elif self.cipher_type == "Caesar":
            message = CaesarCipher.encrypt(message, self.caesar_shift)

        response_packet = f"{response_type},{message}"
        print(f"Sent: {response_packet}")
        self.client_socket.send(response_packet.encode("utf-8"))

    def run(self):
        print(f"Connection from {self.client_address}")
        try:
            while True:
                request = self.client_socket.recv(2048).decode("utf-8")
                if not request:
                    print("Client disconnected.")
                    break

                print(f"Received: {request}")
                fields = request.split(",")
                if fields[0] == "SS":  # Start Packet
                    self.cipher_type = fields[1]  # Set cipher type (AES, Caesar, etc.)
                    public_key_encoded = base64.b64encode(self.server_public_key.export_key()).decode()
                    self.send_response("CC", public_key_encoded)

                elif fields[0] == "EC":  # Encryption Packet
                    encrypted_session_key = base64.b64decode(fields[2])
                    self.session_key = PKCS1_OAEP.new(self.server_private_key).decrypt(encrypted_session_key)
                    print("Session key successfully decrypted.")

                elif fields[0] == "CM":  # Command Packet
                    command = fields[1]
                    args = fields[2] if len(fields) > 2 else ""
                    self.execute_command(command, args)

                elif fields[0] == "End":  # Close Packet
                    print("Client has closed the connection.")
                    break

                else:
                    self.send_response("EE,1001", "Invalid packet type.")
        except Exception as e:
            print(f"Error: {e}")
            self.send_response("EE,1000", f"General error: {str(e)}")
        finally:
            self.client_socket.close()
            print(f"Connection with {self.client_address} closed.")

    def execute_command(self, command, args):
        try:
            if self.cipher_type == "Caesar" and args:
                args = CaesarCipher.decrypt(args, self.caesar_shift)
            elif self.cipher_type == "AES" and args and self.session_key:
                args = Encryptor.aes_decrypt(self.session_key, args)

            if command == "mkdir":
                os.makedirs(args, exist_ok=True)
                self.send_response("SC", f"Directory '{args}' created successfully.")
            elif command == "cd":
                os.chdir(args)
                self.send_response("SC", f"Changed directory to '{args}'.")
            elif command in ("rmdir", "rd"):
                os.rmdir(args)
                self.send_response("SC", f"Directory '{args}' removed successfully.")
            elif command == "del":
                os.remove(args)
                self.send_response("SC", f"File '{args}' deleted successfully.")
            elif command == "ren":
                old_name, new_name = args.split(" ", 1)
                os.rename(old_name, new_name)
                self.send_response("SC", f"Renamed '{old_name}' to '{new_name}'.")
            elif command == "openRead":
                with open(args, "r") as file:
                    data = file.read()
                    if self.cipher_type == "AES" and self.session_key:
                        data = Encryptor.aes_encrypt(self.session_key, data)
                    elif self.cipher_type == "Caesar":
                        data = CaesarCipher.encrypt(data, self.caesar_shift)
                    self.send_response("SC", data)
            elif command == "openWrite":
                with open(args, "w") as file:
                    file.write("Sample content written by server.")
                self.send_response("SC", f"File '{args}' created in write mode.")
            elif command == "date":
                current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.send_response("SC", f"Current Date and Time: {current_date}")
            elif command == "hostname":
                hostname = subprocess.getoutput("hostname")
                self.send_response("SC", f"Hostname: {hostname}")
            elif command == "echo":
                self.send_response("SC", f"ECHO: {args}")
            elif command == "ls":
                directory_content = os.listdir(args if args else ".")
                self.send_response("SC", f"Directory Content: {', '.join(directory_content)}")
            elif command == "pwd":
                current_dir = os.getcwd()
                self.send_response("SC", f"Current Directory: {current_dir}")
            else:
                self.send_response("EE,1002", f"Unknown command '{command}'.")
        except Exception as e:
            print(f"Error executing command: {e}")
            self.send_response("EE,1003", f"Command execution error: {str(e)}")

def server_main():
    host = "127.0.0.1"
    port = 5000

    server_private_key = RSA.generate(2048)
    server_public_key = server_private_key.publickey()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server running on {host}:{port}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            thread = ServerThread(client_socket, client_address, server_private_key, server_public_key)
            thread.start()

    except KeyboardInterrupt:
        print("Server shutting down.")

    finally:
        server_socket.close()

if __name__ == "__main__":
    server_main()

