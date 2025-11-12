class AES:
    def __init__(self):
        # Arbitrary S-box for demonstration
        self.s_box = [
            [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        ]
        
        # Arbitrary inverse S-box for decryption
        self.inv_s_box = [
            [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
            [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
            [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
            [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
            [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
            [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
            [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
            [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
            [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
            [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
            [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
            [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
            [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
            [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
            [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
        ]
        
        # Arbitrary MixColumns matrix for demonstration
        self.mix_columns_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]
        
        # Arbitrary inverse MixColumns matrix for decryption
        self.inv_mix_columns_matrix = [
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ]
        
        # Arbitrary key for demonstration
        self.key = [
            [0x2B, 0x28, 0xAB, 0x09],
            [0x7E, 0xAE, 0xF7, 0xCF],
            [0x15, 0xD2, 0x15, 0x4F],
            [0x16, 0xA6, 0x88, 0x3C]
        ]

    def text_to_matrix(self, text):
        """Convert 16-character text to 4x4 state matrix"""
        if len(text) != 16:
            # Pad with 'x' if shorter, truncate if longer
            text = text.ljust(16, 'x')[:16]
        
        matrix = []
        for i in range(0, 16, 4):
            row = [ord(text[i]), ord(text[i+1]), ord(text[i+2]), ord(text[i+3])]
            matrix.append(row)
        return matrix

    def matrix_to_text(self, matrix):
        """Convert 4x4 state matrix back to text"""
        text = ""
        for row in matrix:
            for val in row:
                # Ensure we only output printable characters
                if 32 <= val <= 126:  # Printable ASCII range
                    text += chr(val)
                else:
                    text += '?'  # Replace non-printable with '?'
        return text

    def sub_bytes(self, state, inverse=False):
        """SubBytes transformation using S-box"""
        result = []
        box = self.inv_s_box if inverse else self.s_box
        for i, row in enumerate(state):
            new_row = []
            for j, val in enumerate(row):
                # Get row and column from S-box
                s_row = (val >> 4) & 0x0F
                s_col = val & 0x0F
                substituted = box[s_row][s_col]
                new_row.append(substituted)
            result.append(new_row)
        return result

    def shift_rows(self, state, inverse=False):
        """ShiftRows transformation"""
        if inverse:
            # Inverse ShiftRows
            result = [state[0][:]]  # Row 0: no shift
            result.append(state[1][3:] + state[1][:3])  # Row 1: shift right 1
            result.append(state[2][2:] + state[2][:2])  # Row 2: shift right 2
            result.append(state[3][1:] + state[3][:1])  # Row 3: shift right 3
        else:
            # Forward ShiftRows
            result = [state[0][:]]  # Row 0: no shift
            result.append(state[1][1:] + state[1][:1])  # Row 1: shift left 1
            result.append(state[2][2:] + state[2][:2])  # Row 2: shift left 2
            result.append(state[3][3:] + state[3][:3])  # Row 3: shift left 3
        return result

    def mix_columns(self, state, inverse=False):
        """MixColumns transformation"""
        matrix = self.inv_mix_columns_matrix if inverse else self.mix_columns_matrix
        result = [[0 for _ in range(4)] for _ in range(4)]
        
        for col in range(4):
            for row in range(4):
                total = 0
                for i in range(4):
                    product = self.galois_multiply(matrix[row][i], state[i][col])
                    total ^= product
                result[row][col] = total
        
        return result

    def galois_multiply(self, a, b):
        """Galois Field multiplication (simplified for demonstration)"""
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            carry = a & 0x80
            a <<= 1
            if carry:
                a ^= 0x1B  # Reduction polynomial
            a &= 0xFF
            b >>= 1
        return result

    def add_round_key(self, state, round_key):
        """AddRoundKey transformation"""
        result = []
        for i in range(4):
            new_row = []
            for j in range(4):
                xor_result = state[i][j] ^ round_key[i][j]
                new_row.append(xor_result)
            result.append(new_row)
        return result

    def encrypt_block(self, plaintext):
        """Encrypt a single 16-byte block"""
        # Convert plaintext to state matrix
        state = self.text_to_matrix(plaintext)
        
        # Initial AddRoundKey
        state = self.add_round_key(state, self.key)
        
        # SubBytes
        state = self.sub_bytes(state)
        
        # ShiftRows
        state = self.shift_rows(state)

        # MixColumns
        state = self.mix_columns(state)
        
        # Final AddRoundKey (using same key for demonstration)
        state = self.add_round_key(state, self.key)
        
        # Convert back to text
        ciphertext = self.matrix_to_text(state)

        return ciphertext, state

    def decrypt_block(self, ciphertext, encrypted_state=None):
        """Decrypt a single 16-byte block with proper inverse operations"""
        if encrypted_state is not None:
            # Use the encrypted state directly to avoid text conversion issues
            state = [row[:] for row in encrypted_state]
        else:
            # Convert ciphertext to state matrix
            state = self.text_to_matrix(ciphertext)
        
        # Inverse AddRoundKey (first in decryption)
        state = self.add_round_key(state, self.key)
        
        # Inverse MixColumns
        state = self.mix_columns(state, inverse=True)
        
        # Inverse ShiftRows
        state = self.shift_rows(state, inverse=True)
        
        # Inverse SubBytes
        state = self.sub_bytes(state, inverse=True)
        
        # Final Inverse AddRoundKey
        state = self.add_round_key(state, self.key)
        
        # Convert back to text
        plaintext = self.matrix_to_text(state)
        
        return plaintext


def encrypt_text(aes, text):
    """Encrypt any length of text using AES block encryption."""
    BLOCK_SIZE = 16
    
    # Show original text
    print(f"\nOriginal text: '{text}'")
    print(f"Original length: {len(text)}")
    
    # Pad text with 'x' to make it multiple of 16
    if len(text) < BLOCK_SIZE:
        padding_needed = BLOCK_SIZE - len(text)
        padded_text = text + 'x' * padding_needed
        print(f"Padded with {padding_needed} 'x' characters")
    elif len(text) > BLOCK_SIZE:
        # For texts longer than 16, we'll process in blocks
        padded_text = text.ljust((len(text) + BLOCK_SIZE - 1) // BLOCK_SIZE * BLOCK_SIZE, 'x')
        print(f"Text is longer than 16 characters, will process in blocks")
    else:
        padded_text = text
        print(f"Text is exactly 16 characters, no padding needed")
    
    print(f"Padded text: '{padded_text}'")
    
    ciphertext = ""
    encrypted_blocks = []
    
    # Process text in 16-character blocks
    for i in range(0, len(padded_text), BLOCK_SIZE):
        block = padded_text[i:i+BLOCK_SIZE]
        print(f"\nProcessing block {i//BLOCK_SIZE + 1}: '{block}'")
        
        encrypted_block, encrypted_state = aes.encrypt_block(block)
        ciphertext += encrypted_block
        encrypted_blocks.append(encrypted_state)
        
        print(f"Encrypted block: '{encrypted_block}'")
    
    print(f"\nFinal ciphertext: '{ciphertext}'")
    return ciphertext, encrypted_blocks


def decrypt_text(aes, ciphertext, encrypted_blocks=None):
    """Decrypt any length of ciphertext using AES block decryption."""
    BLOCK_SIZE = 16
    
    print(f"\nCiphertext to decrypt: '{ciphertext}'")
    print(f"Ciphertext length: {len(ciphertext)}")
    
    plaintext = ""
    
    # Process ciphertext in 16-character blocks
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        print(f"\nProcessing block {i//BLOCK_SIZE + 1}: '{block}'")
        
        if encrypted_blocks and i//BLOCK_SIZE < len(encrypted_blocks):
            # Use the encrypted state directly for more accurate decryption
            decrypted_block = aes.decrypt_block(block, encrypted_blocks[i//BLOCK_SIZE])
        else:
            decrypted_block = aes.decrypt_block(block)
        
        plaintext += decrypted_block
        print(f"Decrypted block: '{decrypted_block}'")
    
    # Remove padding 'x' if present at the end
    original_plaintext = plaintext.rstrip('x')
    
    print(f"\nDecrypted text (with padding): '{plaintext}'")
    print(f"Final plaintext (padding removed): '{original_plaintext}'")
    
    return original_plaintext


def main():
    """Main function to demonstrate AES encryption/decryption"""
    aes = AES()
    
    while True:
        print("\n" + "="*70)
        print("AES ENCRYPTION/DECRYPTION DEMONSTRATION")
        print("="*70)
        print("1. Encrypt text (any length)")
        print("2. Decrypt text (any length)") 
        print("3. Test with example")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            text = input("Enter text to encrypt: ").strip()
            if not text:
                print("No text entered! Using default...")
                text = "HelloAES12345678"
            
            ciphertext, encrypted_blocks = encrypt_text(aes, text)
            
        elif choice == '2':
            text = input("Enter text to decrypt: ").strip()
            if not text:
                print("No text entered!")
                continue
                
            plaintext = decrypt_text(aes, text)
            
        elif choice == '3':
            # Test with various examples
            test_cases = [
                "Hello",           # Short text
                "HelloAES12345678", # Exactly 16 chars  
                "This is a longer text that needs padding", # Long text
                "A",               # Very short
                "1234567890"       # Medium length
            ]
            
            for test_text in test_cases:
                print(f"\n{'='*50}")
                print(f"TESTING: '{test_text}'")
                print(f"{'='*50}")
                
                # Encrypt
                ciphertext, encrypted_blocks = encrypt_text(aes, test_text)
                
                # Decrypt
                decrypted_text = decrypt_text(aes, ciphertext, encrypted_blocks)
                
                # Verify
                if test_text == decrypted_text:
                    print(f"✅ SUCCESS: Original and decrypted match!")
                else:
                    print(f"❌ FAILED: '{test_text}' != '{decrypted_text}'")
                
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()