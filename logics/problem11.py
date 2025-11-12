import secrets
import hashlib
import hmac

class SecureDiffieHellman:
    def __init__(self, prime_bits=2048):
        """
        Enhanced Diffie-Hellman with better security practices
        """
        self.prime_bits = prime_bits
        self.p, self.g = self._generate_safe_prime(prime_bits)
        self.private_key = None
        self.public_key = None
    
    def _generate_safe_prime(self, bits):
        """
        Generate a safe prime (p = 2q + 1 where q is also prime)
        For demonstration, we'll use a predefined safe prime
        """
        # Using a predefined 2048-bit safe prime from RFC 3526
        safe_prime_2048 = int(
            "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        )
        return safe_prime_2048, 2
    
    def generate_private_key(self):
        """
        Generate cryptographically secure private key
        """
        # Use secrets module for cryptographically secure random numbers
        self.private_key = secrets.randbelow(self.p - 2) + 1
        return self.private_key
    
    def generate_public_key(self):
        """
        Generate public key using modular exponentiation
        """
        if self.private_key is None:
            self.generate_private_key()
        
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):
        """
        Compute shared secret with validation
        """
        if self.private_key is None:
            raise ValueError("Private key not generated")
        
        # Validate the other public key
        if not (1 < other_public_key < self.p - 1):
            raise ValueError("Invalid public key")
        
        return pow(other_public_key, self.private_key, self.p)
    
    def derive_secure_key(self, shared_secret, salt=None, info=b"diffie-hellman"):
        """
        Derive secure key using HKDF (HMAC-based Key Derivation Function)
        """
        # HKDF-Extract
        if salt is None:
            salt = b"\x00" * 32  # Zero salt if not provided
        
        prk = hmac.new(salt, shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big'), hashlib.sha256).digest()
        
        # HKDF-Expand
        info = info + b"\x01"  # Add counter
        derived_key = hmac.new(prk, info, hashlib.sha256).digest()
        
        return derived_key

# Example usage of the enhanced version
def enhanced_demo():
    print("=== Enhanced Diffie-Hellman Demo ===\n")
    
    alice = SecureDiffieHellman()
    bob = SecureDiffieHellman()
    
    # Ensure both use same parameters
    bob.p = alice.p
    bob.g = alice.g
    
    # Generate keys
    alice.generate_private_key()
    bob.generate_private_key()
    
    alice_public = alice.generate_public_key()
    bob_public = bob.generate_public_key()
    
    print("Public Keys Generated:")
    print(f"Alice: {alice_public}")
    print(f"Bob: {bob_public}\n")
    
    # Compute shared secrets
    alice_secret = alice.compute_shared_secret(bob_public)
    bob_secret = bob.compute_shared_secret(alice_public)
    
    print("Shared Secrets Computed:")
    print(f"Match: {alice_secret == bob_secret}\n")
    
    # Derive secure keys
    alice_key = alice.derive_secure_key(alice_secret)
    bob_key = bob.derive_secure_key(bob_secret)
    
    print("Derived Keys:")
    print(f"Alice: {alice_key.hex()}")
    print(f"Bob: {bob_key.hex()}")
    print(f"Match: {alice_key == bob_key}")

if __name__ == "__main__":
    enhanced_demo()