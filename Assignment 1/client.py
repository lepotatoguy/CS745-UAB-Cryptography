import socket
import os
from ascon import ascon_encrypt, ascon_decrypt


# nonce = bytes([0] * 16)
client_key = b'1234567890123456'
server_key = b'9876543210654321'
nonce = b'nonce123nonce456'
Associate_Data = "CS645/745 Modern Cryptography: Secure Messaging"


def Decrypt_Text(cipher_text):
    print(
        f"Decrypting: Key Length: {len(server_key)}, Nonce Length: {len(nonce)}, CipherText Length: {len(cipher_text)}")
    decrypt_texts = ascon_decrypt(
        server_key, nonce, Associate_Data, cipher_text)
    if decrypt_texts is not None:  # Check if decrypt_texts is not None
        return decrypt_texts.decode()  # Safe to decode if it's not None
    else:
        # Handle the case where decryption verification fails
        print("Decryption failed or verification failed.")
        return None  # Or handle it differently based on your application's requirements


def Encrypt_Text(PlainText):
    # Assuming this function returns the encrypted data as bytes
    cipher_text = ascon_encrypt(
        client_key, nonce, Associate_Data, PlainText.encode())
    return cipher_text


def receive_and_decrypt_message(sock):
    try:
        # Receive the length of the encrypted message first
        encrypted_message_length = sock.recv(1024).decode('utf-8')
        if not encrypted_message_length:
            print("Server closed the connection.")
            return None
        message_length = int(encrypted_message_length)

        # Now, receive the encrypted message based on its length
        encrypted_message = b''
        while len(encrypted_message) < message_length:
            part = sock.recv(message_length - len(encrypted_message))
            if part == '':
                print("Connection closed by the server.")
                break
            encrypted_message += part

        # Decrypt the received message
        decrypted_message = Decrypt_Text(encrypted_message)
        if decrypted_message is not None:
            print(f"Message from server: {decrypted_message}")
        else:
            print("Failed to decrypt the message from the server.")
    except Exception as e:
        print(f"An error occurred while receiving a message: {e}")


def start_client(server_host='127.0.0.1', server_port=12348):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_host, server_port))
        print("Connected to the server. You can start sending messages.")

        while True:
            message = input("Enter your Text: ")
            if message:
                Encrypted_Text = Encrypt_Text(message)
                # Send the length of the encrypted text first
                message_length = str(len(Encrypted_Text))
                print(message_length)
                client_socket.send(message_length.encode('utf-8'))

                # Wait for server acknowledgment (optional step for synchronization)
                # ack = client_socket.recv(1024)  # This could be a simple 'OK' from the server

                # Now, send the actual encrypted message
                client_socket.send(Encrypted_Text)

                # Wait for and decrypt the response from the server
                receive_and_decrypt_message(client_socket)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()
        print("Disconnected from the server.")


if __name__ == "__main__":
    start_client()
