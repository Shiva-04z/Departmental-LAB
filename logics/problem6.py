class RC4:
    """
    RC4 Stream Cipher Implementation
    """
    
    def __init__(self, key):
        """
        Initialize RC4 with the given key
        
        Args:
            key: Secret key as bytes or string
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        self.key = key
        self.S = list(range(256))
        self._key_scheduling()
    
    def _key_scheduling(self):
        """Key Scheduling Algorithm (KSA)"""
        j = 0
        key_length = len(self.key)
        
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def _pseudo_random_generation(self, data_length):
        """Pseudo-Random Generation Algorithm (PRGA)"""
        i = j = 0
        keystream = []
        
        for _ in range(data_length):
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            
            k = self.S[(self.S[i] + self.S[j]) % 256]
            keystream.append(k)
        
        return keystream
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using RC4
        
        Args:
            plaintext: Data to encrypt as bytes or string
            
        Returns:
            Encrypted data as bytes
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        keystream = self._pseudo_random_generation(len(plaintext))
        
        # XOR each byte of plaintext with keystream
        ciphertext = bytes([plaintext[i] ^ keystream[i] for i in range(len(plaintext))])
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using RC4
        
        Args:
            ciphertext: Data to decrypt as bytes
            
        Returns:
            Decrypted data as bytes
        """
        # RC4 is symmetric - encryption and decryption are the same operation
        return self.encrypt(ciphertext)


def bytes_to_hex(data):
    """Convert bytes to hexadecimal string"""
    return data.hex()


def hex_to_bytes(hex_string):
    """Convert hexadecimal string to bytes"""
    return bytes.fromhex(hex_string)


def demo_rc4():
    """Demonstrate RC4 encryption and decryption"""
    print("RC4 Stream Cipher Demonstration")
    print("=" * 40)
    
    # Test cases
    test_cases = [
        {
            "key": "SecretKey",
            "plaintext": "Hello, World! This is RC4 encryption."
        },
        {
            "key": "MyPassword123",
            "plaintext": "Sensitive data that needs protection."
        },
        {
            "key": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
            "plaintext": "Binary key example"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Key: {test_case['key']}")
        print(f"Plaintext: {test_case['plaintext']}")
        
        # Initialize RC4 with key
        rc4 = RC4(test_case['key'])
        
        # Encrypt
        ciphertext = rc4.encrypt(test_case['plaintext'])
        print(f"Ciphertext (hex): {bytes_to_hex(ciphertext)}")
        
        # Re-initialize for decryption (to reset the state)
        rc4_decrypt = RC4(test_case['key'])
        
        # Decrypt
        decrypted = rc4_decrypt.decrypt(ciphertext)
        print(f"Decrypted: {decrypted.decode('utf-8')}")
        
        # Verify
        if decrypted.decode('utf-8') == test_case['plaintext']:
            print("✓ Encryption/Decryption successful!")
        else:
            print("✗ Encryption/Decryption failed!")
        
        print("-" * 40)


def file_encryption_example():
    """Example of encrypting and decrypting a file"""
    print("\nFile Encryption Example")
    print("=" * 40)
    
    # Sample file content
    file_content = "This is a secret file content that needs to be encrypted.\nLine 2 of the file.\nLine 3 with special characters: !@#$%^&*()"
    
    key = "FileEncryptionKey"
    
    # Encrypt file content
    rc4 = RC4(key)
    encrypted_content = rc4.encrypt(file_content)
    
    print(f"Original file size: {len(file_content)} bytes")
    print(f"Encrypted file size: {len(encrypted_content)} bytes")
    print(f"Encrypted content (first 50 bytes hex): {bytes_to_hex(encrypted_content[:50])}...")
    
    # Decrypt file content
    rc4_decrypt = RC4(key)
    decrypted_content = rc4_decrypt.decrypt(encrypted_content)
    
    print(f"Decrypted content matches original: {decrypted_content.decode('utf-8') == file_content}")
    print("File encryption/decryption completed successfully!")


    print("=" * 50)


if __name__ == "__main__":
     
    try:
        key = input("Enter encryption key: ")
        message = input("Enter message to encrypt: ")
        
        rc4 = RC4(key)
        encrypted = rc4.encrypt(message)
        
        print(f"\nEncrypted (hex): {bytes_to_hex(encrypted)}")
        
        # Decrypt
        rc4_decrypt = RC4(key)
        decrypted = rc4_decrypt.decrypt(encrypted)
        
        print(f"Decrypted: {decrypted.decode('utf-8')}")
        
    except Exception as e:
        print(f"Error: {e}")