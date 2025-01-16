import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

# Generate AES Key
def generate_aes_key():
    return os.urandom(32)  # AES-256 key size

# Generate RSA Keys for encryption of RSA key and digital signatures
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save RSA keys securely in PKCS12 format
def save_rsa_key(private_key, public_key, user_id):
    p12_data = serialize_key_and_certificates(
        name=b"user_key",
        key=private_key,
        cert=None, 
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"Thisissecret")
    )
    # Save the PKCS12 bundle to a file
    with open(f"{user_id}_keys.p12", "wb") as f:
        f.write(p12_data)

# Encrypt AES Key with RSA Public Key
def encrypt_key_with_rsa(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Decrypt AES Key with RSA Private Key
def decrypt_key_with_rsa(encrypted_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Encryptiobn of File with AES-GCM Mode
def encrypt_file(aes_key):
    file_path = r"C:\\Users\\Ali Abbasi\\Desktop\\Semester 1\\Crypto assessment\\python\\AES-RSA-HMAC\\plaintext-ali.txt"

    # Check if file exists
    if not os.path.isfile(file_path):
        print("File does not exist at specified path.")
        return

    try:
        # Read file data
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # AES-GCM mode for encryption and integrity
        iv = os.urandom(12)  # 12 Byte Random IV for AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Save encrypted data (IV, tag, and ciphertext)
        with open(f"{file_path}.enc", "wb") as f:
            f.write(iv + encryptor.tag + ciphertext)

        print(f"File {file_path} encrypted successfully.")
    except Exception as e:
        print(f"An error occurred during encryption: {e}")

# Decrypt File with AES-GCM
def decrypt_file(encrypted_file_path, aes_key):
    try:
        with open(encrypted_file_path, 'rb') as f:
            iv = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        # AES-GCM decryption
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Save decrypted data
        with open(f"{encrypted_file_path}.dec", "wb") as f:
            f.write(plaintext)

        print(f"File {encrypted_file_path} decrypted successfully.")
    except Exception as e:
        print(f"An error occurred during decryption: {e}")

# Generate HMAC for Data Integrity
def generate_hmac(data, aes_key):
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Sign the Encrypted Data with RSA Private Key for Authenticity
def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify the Digital Signature with RSA Public Key
def verify_signature(data, signature, public_key):
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
        print("Didital Signature verified successfully.")
    except InvalidSignature:
        print("Digital Signature verification failed.")

if __name__ == "__main__":
    # Step 1: Generate AES key
    aes_key = generate_aes_key()

    # Step 2: Encrypt the file
    encrypt_file(aes_key)

    # Step 3: Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Save RSA keys using PKCS12
    save_rsa_key(private_key, public_key, user_id="user1")

    # Step 4: Encrypt AES key with RSA
    encrypted_aes_key = encrypt_key_with_rsa(aes_key, public_key)

    # Save the encrypted AES key
    with open("encrypted_aes_key.bin", "wb") as f:
        f.write(encrypted_aes_key)

    print("Encrypted AES key has been saved.")

    # Step 5: Generate HMAC for encrypted file
    encrypted_file_path = r"C:\\Users\\Ali Abbasi\\Desktop\\Semester 1\\Crypto assessment\\python\\AES-RSA-HMAC\\plaintext-ali.txt.enc"
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    hmac_value = generate_hmac(encrypted_data, aes_key)

    # Save HMAC
    with open("hmac_value.bin", "wb") as f:
        f.write(hmac_value)

    # Step 6: Sign encrypted data
    signature = sign_data(encrypted_data, private_key)

    # Save signature
    with open("signature.bin", "wb") as f:
        f.write(signature)

    # Step 7: Decrypt the AES key using the RSA private key
    with open("encrypted_aes_key.bin", "rb") as f:
        encrypted_aes_key = f.read()

    decrypted_aes_key = decrypt_key_with_rsa(encrypted_aes_key, private_key)
    print("AES key has been decrypted successfully.")

    # Step 8: Verify HMAC
    with open("hmac_value.bin", "rb") as f:
        expected_hmac = f.read()
    h = hmac.HMAC(decrypted_aes_key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    try:
        h.verify(expected_hmac)
        print("HMAC integrity has been verified.")
    except InvalidSignature:
        print("HMAC integrity check is failed!")
        exit()

    # Step 9: Decrypt the file
    decrypt_file(encrypted_file_path, decrypted_aes_key)

    # Step 10: Verify signature using RSA public Key
    with open("signature.bin", "rb") as f:
        signature = f.read()
    verify_signature(encrypted_data, signature, public_key)
