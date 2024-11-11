import hashlib

class EncryptionUtility:
    def __init__(self, key):
        self.key = key.encode()

    def compute_sha256_fingerprint(self):
        """Compute SHA-256 hash (not quantum-safe)"""
        digest = hashlib.new("sha256") 
        digest.update(self.key)
        return digest.hexdigest()

try:
    utility = EncryptionUtility("supersecretkey")
    print("SHA-256 Fingerprint (not quantum-safe):", utility.compute_sha256_fingerprint())
except Exception as e:
    print("Error during encryption:", e)