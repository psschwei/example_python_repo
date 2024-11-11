from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class EncryptionUtility:
    def __init__(self, key):
        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key)

    def encrypt_message(self, message):
        """Encrypt message using RSA (not quantum-safe)"""
        encrypted_message = self.cipher.encrypt(message.encode())
        return encrypted_message

try:
    utility = EncryptionUtility("public_key")
    encrypted = utility.encrypt_message("secret message")
    print("Encrypted Message (not quantum-safe):", encrypted)
except Exception as e:
    print("Error during encryption:", e)
