import socket
import threading
import os
from ascon import ascon_encrypt, ascon_decrypt

# nonce = bytes([0] * 16)
client_key = b'1234567890123456'
server_key = b'9876543210654321'
nonce = b'nonce123nonce456'
Associate_Data = "CS645/745 Modern Cryptography: Secure Messaging"


def Encrypt_Text(PlainText):
    cipher_text = ascon_encrypt(
        server_key, nonce, Associate_Data, PlainText.encode())
    return cipher_text


def Decrypt_Text(cipher_text):
    print(
        f"Decrypting: Key Length: {len(client_key)}, Nonce Length: {len(nonce)}, CipherText Length: {len(cipher_text)}")
    decrypt_texts = ascon_decrypt(
        client_key, nonce, Associate_Data, cipher_text)
    if decrypt_texts is not None:  # Check if decrypt_texts is not None
        return decrypt_texts.decode()  # Safe to decode if it's not None
    else:
        # Handle the case where decryption verification fails
        print("Decryption failed or verification failed.")
        return None  # Or handle it differently based on your application's requirements


def handle_client(client_socket):
    try:
        while True:
            # Receive the length of the message first
            raw_message_length = client_socket.recv(1024)
            if raw_message_length == b'':  # Client closed connection
                print("Client has closed the connection.")
                break

            try:
                message_length = int(raw_message_length.decode('utf-8'))
                print(message_length)
            except ValueError:
                print(message_length)
                # This block catches decoding errors or if the decoded value cannot be converted to an integer
                print("Received message length is not an integer.")
                break

            # Receive the actual message
            message = b''
            while len(message) < message_length:
                part = client_socket.recv(message_length - len(message))
                if part == b'':
                    print("Connection closed before receiving the full message.")
                    return  # Exit function as the connection is considered closed
                message += part

            # At this point, `message` contains the full data
            Decrypted_Text = Decrypt_Text(message)
            print(f"Received message from client: {Decrypted_Text}")

            Response = input("Enter your message: ")
            Encrypted_Response = Encrypt_Text(Response)
            client_socket.send(str(len(Encrypted_Response)).encode('utf-8'))
            client_socket.send(Encrypted_Response)

    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        client_socket.close()
        print("Connection with client has been terminated.")


def start_server(host='0.0.0.0', port=12348):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        client, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()


if __name__ == "__main__":
    start_server()
