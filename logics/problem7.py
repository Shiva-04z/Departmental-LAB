import random
import math
import base64
from typing import Tuple, Union

class RSA:
    """
    RSA Public Key Cryptography Implementation
    """
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize RSA with specified key size
        
        Args:
            key_size: Key size in bits (default: 2048)
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
    
    def is_prime(self, n: int, k: int = 5) -> bool:
        """
        Miller-Rabin primality test
        
        Args:
            n: Number to test
            k: Number of test iterations
            
        Returns:
            True if n is probably prime
        """
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False
        
        # Write n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Test k times
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def generate_large_prime(self, bits: int) -> int:
        """
        Generate a large prime number
        
        Args:
            bits: Number of bits for the prime
            
        Returns:
            A large prime number
        """
        while True:
            # Generate odd number with specified bits
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1  # Set highest and lowest bits
            
            if self.is_prime(num):
                return num
    
    def gcd(self, a: int, b: int) -> int:
        """
        Euclidean algorithm for Greatest Common Divisor
        """
        while b:
            a, b = b, a % b
        return a
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm
        Returns (gcd, x, y) such that ax + by = gcd(a, b)
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def mod_inverse(self, a: int, m: int) -> int:
        """
        Compute modular inverse using extended Euclidean algorithm
        
        Args:
            a: Number
            m: Modulus
            
        Returns:
            Modular inverse of a mod m
        """
        gcd, x, _ = self.extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}")
        
        return x % m
    
    def generate_key_pair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA public and private key pair
        
        Returns:
            Tuple of (public_key, private_key) where:
            public_key = (n, e)
            private_key = (n, d)
        """
        print(f"Generating {self.key_size}-bit RSA key pair...")
        
        # Generate two large primes
        p_bits = self.key_size // 2
        q_bits = self.key_size - p_bits
        
        p = self.generate_large_prime(p_bits)
        q = self.generate_large_prime(q_bits)
        
        while p == q:
            q = self.generate_large_prime(q_bits)
        
        print(f"Generated primes: p ({p.bit_length()} bits), q ({q.bit_length()} bits)")
        
        # Compute n = p * q
        n = p * q
        self.n = n
        
        # Compute Euler's totient function φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)
        
        # Choose public exponent e
        e = 65537  # Common choice for e
        while self.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        
        # Compute private exponent d
        d = self.mod_inverse(e, phi)
        
        self.public_key = (n, e)
        self.private_key = (n, d)
        
        print(f"Key generation completed!")
        print(f"n: {n.bit_length()} bits")
        print(f"e: {e}")
        
        return self.public_key, self.private_key
    
    def encrypt(self, message: Union[str, bytes], public_key: Tuple[int, int] = None) -> bytes:
        """
        Encrypt message using RSA public key
        
        Args:
            message: Message to encrypt (string or bytes)
            public_key: Public key (n, e), uses instance key if None
            
        Returns:
            Encrypted message as bytes
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available")
            public_key = self.public_key
        
        n, e = public_key
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Convert message to integer
        m_int = int.from_bytes(message, 'big')
        
        # Check if message is too long
        max_len = (n.bit_length() - 1) // 8
        if len(message) > max_len:
            raise ValueError(f"Message too long. Maximum length is {max_len} bytes")
        
        # Encrypt: c = m^e mod n
        c_int = pow(m_int, e, n)
        
        # Convert back to bytes
        ciphertext = c_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, private_key: Tuple[int, int] = None) -> str:
        """
        Decrypt ciphertext using RSA private key
        
        Args:
            ciphertext: Encrypted message as bytes
            private_key: Private key (n, d), uses instance key if None
            
        Returns:
            Decrypted message as string
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available")
            private_key = self.private_key
        
        n, d = private_key
        
        # Convert ciphertext to integer
        c_int = int.from_bytes(ciphertext, 'big')
        
        # Check if ciphertext is valid
        if c_int >= n:
            raise ValueError("Ciphertext too large")
        
        # Decrypt: m = c^d mod n
        m_int = pow(c_int, d, n)
        
        # Convert back to bytes and then to string
        # Calculate the expected length of the original message
        message_len = (m_int.bit_length() + 7) // 8
        message = m_int.to_bytes(message_len, 'big')
        
        return message.decode('utf-8')
    
    def encrypt_long_message(self, message: str, public_key: Tuple[int, int] = None) -> list:
        """
        Encrypt long message by splitting into chunks
        
        Args:
            message: Long message to encrypt
            public_key: Public key to use
            
        Returns:
            List of encrypted chunks
        """
        if public_key is None:
            public_key = self.public_key
        
        n, e = public_key
        max_chunk_size = (n.bit_length() - 1) // 8
        
        encrypted_chunks = []
        message_bytes = message.encode('utf-8')
        
        for i in range(0, len(message_bytes), max_chunk_size):
            chunk = message_bytes[i:i + max_chunk_size]
            encrypted_chunk = self.encrypt(chunk, public_key)
            encrypted_chunks.append(encrypted_chunk)
        
        return encrypted_chunks
    
    def decrypt_long_message(self, encrypted_chunks: list, private_key: Tuple[int, int] = None) -> str:
        """
        Decrypt long message from chunks
        
        Args:
            encrypted_chunks: List of encrypted chunks
            private_key: Private key to use
            
        Returns:
            Decrypted message
        """
        decrypted_chunks = []
        
        for chunk in encrypted_chunks:
            decrypted_chunk = self.decrypt(chunk, private_key)
            decrypted_chunks.append(decrypted_chunk)
        
        return ''.join(decrypted_chunks)


def bytes_to_base64(data: bytes) -> str:
    """Convert bytes to base64 string"""
    return base64.b64encode(data).decode('utf-8')


def base64_to_bytes(data: str) -> bytes:
    """Convert base64 string to bytes"""
    return base64.b64decode(data.encode('utf-8'))


def demo_rsa():
    
    
    # Initialize RSA with 1024-bit keys for faster demonstration
    rsa = RSA(key_size=1024)
    
    # Generate key pair
    public_key, private_key = rsa.generate_key_pair()
    n, e = public_key
    n_priv, d = private_key
    
    print(f"\nPublic Key (n, e):")
    print(f"n: {n}")
    print(f"e: {e}")
    
    print(f"\nPrivate Key (n, d):")
    print(f"n: {n_priv}")
    print(f"d: [HIDDEN for security]")
    
    # Test messages
    test_messages = [
        "Hello, RSA!",
        "Secret message 123",
        "The quick brown fox jumps over the lazy dog",
        "RSA is asymmetric cryptography!"
    ]
    
    print(f"\nEncryption/Decryption Tests:")
    print("-" * 40)
    
    for i, message in enumerate(test_messages, 1):
        print(f"\nTest {i}:")
        print(f"Original: {message}")
        
        # Encrypt
        ciphertext = rsa.encrypt(message)
        print(f"Encrypted (base64): {bytes_to_base64(ciphertext)}")
        
        # Decrypt
        decrypted = rsa.decrypt(ciphertext)
        print(f"Decrypted: {decrypted}")
        
        # Verify
        if decrypted == message:
            print("✓ Success!")
        else:
            print("✗ Failed!")
    
    return rsa, public_key, private_key


if __name__ == "__main__":
    # Main demonstration
    rsa, public_key, private_key = demo_rsa()
    
    
    try:
        message = input("Enter a message to encrypt: ")
        
        if len(message) > 100:  # For long messages
            encrypted_chunks = rsa.encrypt_long_message(message)
            decrypted = rsa.decrypt_long_message(encrypted_chunks)
            print(f"Encrypted into {len(encrypted_chunks)} chunks")
        else:
            ciphertext = rsa.encrypt(message)
            decrypted = rsa.decrypt(ciphertext)
            print(f"Encrypted (base64): {bytes_to_base64(ciphertext)}")
        
        print(f"Decrypted: {decrypted}")
        
    except Exception as e:
        print(f"Error: {e}")