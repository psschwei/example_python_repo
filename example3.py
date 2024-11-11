from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

class AESEncryptionUtility:
    def __init__(self, key):
        # AES-128 key (not quantum-safe, and ECB mode is insecure)
        self.key = key[:16].encode("utf-8").ljust(16, b'\0')  # Ensure key is 128 bits
        self.cipher = AES.new(self.key, AES.MODE_ECB)  # ECB mode

    def encrypt_message(self, plaintext):
        """Encrypt message using AES-128 in ECB mode (not quantum-safe and insecure)"""
        padded_plaintext = plaintext.ljust((len(plaintext) + 15) // 16 * 16)  # Pad to block size
        encrypted_data = self.cipher.encrypt(padded_plaintext.encode())
        return b64encode(encrypted_data).decode("utf-8")

    def decrypt_message(self, encrypted_message):
        """Decrypt AES-128 ECB encrypted message"""
        encrypted_data = b64decode(encrypted_message)
        decrypted_data = self.cipher.decrypt(encrypted_data)
        return decrypted_data.decode("utf-8").strip()

try:
    utility = AESEncryptionUtility("simplekey123")
    encrypted = utility.encrypt_message("This is a sensitive message.")
    print("Encrypted Message (not quantum-safe, ECB mode):", encrypted)
    decrypted = utility.decrypt_message(encrypted)
    print("Decrypted Message:", decrypted)
except Exception as e:
    print("Error during encryption/decryption:", e)
