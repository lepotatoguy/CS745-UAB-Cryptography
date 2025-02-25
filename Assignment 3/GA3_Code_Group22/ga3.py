from hashlib import sha256  # For Merkle hashing
from ascon import ascon_hash
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import time  # For timestamps


# If error comes up of .DS_Store
# find . -name "*.DS_Store" -type f -delete



def calculate_file_hash(file_path):
    hasher = sha256()  # Or any other suitable hash function
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)  # Read in chunks
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def calculate_merkle_hash(directory_path):
    hashes = []
    for item in os.listdir(directory_path):
        item_path = os.path.join(directory_path, item)
        if os.path.isfile(item_path):
            file_hash_bytes = bytes.fromhex(calculate_file_hash(item_path))
            hashes.append(file_hash_bytes)
        elif os.path.isdir(item_path):
            hashes.append(calculate_merkle_hash(item_path))

    # Build the Merkle tree (simplified binary tree example)
    while len(hashes) > 1:
        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined_hash = ascon_hash(
                (hashes[i] + hashes[i + 1]), variant="Ascon-Hash", hashlength=32)
            new_hashes.append(combined_hash)
        hashes = new_hashes
    return hashes[0].hex()  # Merkle root


def generate_hash_chain(snapshots_dir, hash_store_file, private_key, public_key):
    with open(hash_store_file, "a+") as file:
        previous_timestamp = None
        previous_signature = None

        print("Iteration Started")
        for day_dir in sorted(os.listdir(snapshots_dir)):  # Process days in order
            snapshot_dir = os.path.join(snapshots_dir, day_dir)
            merkle_root = calculate_merkle_hash(snapshot_dir)

            # Read the existing hash from the file (if available)
            previous_data_str = file.readline().strip()
            print("Existing data from file:", previous_data_str) 
            if previous_data_str:
                # 1. Read combined data from file
                previous_data = previous_data_str.encode()

                # 2. Split combined data
                previous_merkle_root, previous_timestamp = previous_data.split(
                    b'|')
                previous_merkle_root = previous_merkle_root.decode()
                print("Previous Merkle Root (from file, decoded):", previous_merkle_root) 
                print("Previous Timestamp (from file, decoded):", previous_timestamp.decode())

                print(type(previous_merkle_root), type(merkle_root))
                data_to_verify = previous_merkle_root.encode()

                
                print("Data being verified (before verification):", data_to_verify)  # For debugging
                # 3. Verification
                try:
                    public_key.verify(
                        previous_signature,
                        data_to_verify,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print("Verification Successful!")
                except InvalidSignature:
                    print(f"Verification failed for timestamp: {
                          previous_timestamp.decode()}")


            timestamp = generate_timestamp()
            print("Timestamp:", timestamp)
            print("Type of Merkle Root:", type(merkle_root))
            # Should be <class 'bytes'> if it's already bytes
            print(type(merkle_root))
            if type(merkle_root) == str:
                merkle_root = bytes.fromhex(
                    merkle_root)  # Convert back to bytes
            data_to_sign = merkle_root
            print("Data to sign (before signing):", data_to_sign) 
            signature = sign_data(private_key, data_to_sign)
            print("Signature:", signature) 

            # Write the new entry to the file
            file.write(f"{timestamp} {merkle_root.hex()}|{signature.hex()}\n")

            previous_timestamp = timestamp
            previous_signature = signature
            # Reset file pointer to the beginning
            file.seek(0)


def sign_data(private_key, data):
    """
    Signs data using the provided private key and SHA-256 hash algorithm.

    Args:
     private_key (cryptography.hazmat.primitives.asymmetric.rsa.PrivateKey):
      The private key object.
     data (str): The data to be signed.

    Returns:
     bytes: The signature.
    """
    print("Data to sign (inside sign_data function):", data) 
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, signature, data):
    """
    Verifies an RSA signature using the provided public key.

    Args:
      public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        The public key object.
      signature (bytes): The signature to verify.
      data (str): The original data that was signed.

    Returns:
      bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Verification successful
    except InvalidSignature:
        return False  # Verification failed

def generate_and_save_key_pair(private_key_file, public_key_file, key_size=2048):
    """
    Generates an RSA key pair and saves the private and public keys to PEM-encoded files.

    Args:
      private_key_file (str): The path to save the private key file (PEM format).
      public_key_file (str): The path to save the public key file (PEM format).
      key_size (int, optional): The key size in bits (default: 2048).
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize and write private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_file, 'wb') as f:
        f.write(pem)

    # Serialize and write public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_file, 'wb') as f:
        f.write(pem)

    print("Key pair generated and saved to:",
          private_key_file, public_key_file)


def generate_key_pair(key_size=2048):
    """
    Generates a new RSA key pair.

    Args:
     key_size (int, optional): The key size in bits (default: 2048).

    Returns:
     tuple: A tuple containing the private key and public key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key



def load_key_pair(private_key_file, public_key_file):
    """
    Loads an existing RSA key pair from PEM-encoded files.

    Args:
     private_key_file (str): The path to the private key file (PEM format).
     public_key_file (str): The path to the public key file (PEM format).

    Returns:
     tuple: A tuple containing the private key and public key objects,
      or None if either file is not found.
    """
    try:
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return private_key, public_key
    except (FileNotFoundError, ValueError, TypeError):
        print(f"Error: Failed to load key pair from files.")
        return None


def generate_timestamp():
    timestamp = int(time.time())
    return str(timestamp)  # Convert to string for easier concatenation


if __name__ == "__main__":
    private_key_file = "private.pem"
    public_key_file = "public.pem"

    # Check if files already exist
    if not os.path.exists(private_key_file) or not os.path.exists(public_key_file):
        generate_and_save_key_pair(private_key_file, public_key_file)
        print("Keys created for the first time")
    else:
        print("Keys already exist. Skipping generation.")
    snapshots_dir = "snapshots"
    hash_store_file = "hash_chain.txt"
    private_key, public_key = generate_key_pair()  # Or load keys

    private_key, public_key = load_key_pair(private_key_file, public_key_file)
    if private_key and public_key:
        generate_hash_chain(snapshots_dir, hash_store_file,
                            private_key, public_key)
    else:
        print("Error: Could not load keys. Exiting.")
