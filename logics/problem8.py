import hashlib

class HashGenerator:
    """
    Hash Generator and Verifier for MD5, SHA-1, and SHA-256
    """
    
    def __init__(self):
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
    
    def generate_hash(self, text: str, algorithm: str = 'sha256') -> str:
        """
        Generate hash for given text using specified algorithm
        
        Args:
            text: Input text string
            algorithm: Hash algorithm to use ('md5', 'sha1', or 'sha256')
            
        Returns:
            Hexadecimal hash string
            
        Raises:
            ValueError: If unsupported algorithm is specified
        """
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Supported: md5, sha1, sha256")
        
        # Convert text to bytes and generate hash
        text_bytes = text.encode('utf-8')
        hash_func = self.supported_algorithms[algorithm.lower()]()
        hash_func.update(text_bytes)
        
        return hash_func.hexdigest()
    
    def generate_all_hashes(self, text: str) -> dict:
        """
        Generate hashes using all three algorithms (MD5, SHA-1, SHA-256)
        
        Args:
            text: Input text string
            
        Returns:
            Dictionary with algorithm names as keys and hash values as values
        """
        hashes = {}
        for algo in self.supported_algorithms:
            hashes[algo] = self.generate_hash(text, algo)
        return hashes
    
    def verify_hash(self, text: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify if text matches the expected hash
        
        Args:
            text: Input text string to verify
            expected_hash: Expected hash value to compare against
            algorithm: Hash algorithm to use for verification
            
        Returns:
            True if generated hash matches expected hash, False otherwise
        """
        actual_hash = self.generate_hash(text, algorithm)
        return actual_hash == expected_hash.lower()


def interactive_mode():
    """
    Interactive mode for users to generate and verify hashes
    """
    hash_gen = HashGenerator()
    
    print("\nInteractive Hash Generator")
    print("=" * 30)
    
    while True:
        print("\nOptions:")
        print("1. Generate hash for a string")
        print("2. Generate all hashes (MD5, SHA-1, SHA-256) for a string")
        print("3. Verify a hash")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            text = input("Enter text to hash: ")
            algorithm = input("Enter algorithm (md5/sha1/sha256): ").strip().lower()
            
            if algorithm not in ['md5', 'sha1', 'sha256']:
                print("Invalid algorithm. Using SHA-256 as default.")
                algorithm = 'sha256'
            
            try:
                hash_value = hash_gen.generate_hash(text, algorithm)
                print(f"\n{algorithm.upper()} hash: {hash_value}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '2':
            text = input("Enter text to hash: ")
            
            try:
                hashes = hash_gen.generate_all_hashes(text)
                print(f"\nAll hashes for '{text}':")
                print(f"MD5:    {hashes['md5']}")
                print(f"SHA-1:  {hashes['sha1']}")
                print(f"SHA-256: {hashes['sha256']}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            text = input("Enter text to verify: ")
            expected_hash = input("Enter expected hash: ").strip()
            algorithm = input("Enter algorithm (md5/sha1/sha256): ").strip().lower()
            
            if algorithm not in ['md5', 'sha1', 'sha256']:
                print("Invalid algorithm. Using SHA-256 as default.")
                algorithm = 'sha256'
            
            try:
                is_valid = hash_gen.verify_hash(text, expected_hash, algorithm)
                print(f"\nVerification result: {'✓ VALID - Hashes match!' if is_valid else '✗ INVALID - Hashes do not match!'}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '4':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")




if __name__ == "__main__":
    interactive_mode()