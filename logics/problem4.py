import binascii

# DES Tables (simplified for correctness)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# S-boxes
S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9, 1,
       58, 50, 42, 34, 26, 18, 10, 2,
       59, 51, 43, 35, 27, 19, 11, 3,
       60, 52, 44, 36, 63, 55, 47, 39,
       31, 23, 15, 7, 62, 54, 46, 38,
       30, 22, 14, 6, 61, 53, 45, 37,
       29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

class DES:
    def __init__(self, key):
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 characters long")
        self.key = key
        self.subkeys = self._generate_subkeys()
    
    def _string_to_bits(self, s):
        """Convert string to list of bits (big-endian)"""
        bits = []
        for char in s:
            # Get 8-bit representation
            val = ord(char)
            for i in range(7, -1, -1):
                bits.append((val >> i) & 1)
        return bits
    
    def _bits_to_string(self, bits):
        """Convert list of bits to string"""
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) < 8:
                break
            val = 0
            for bit in byte:
                val = (val << 1) | bit
            chars.append(chr(val))
        return ''.join(chars)
    
    def _bytes_to_bits(self, data):
        """Convert bytes to list of bits"""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    
    def _bits_to_bytes(self, bits):
        """Convert list of bits to bytes"""
        data = bytearray()
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            if len(byte_bits) < 8:
                # Pad with zeros if needed
                byte_bits = byte_bits + [0] * (8 - len(byte_bits))
            byte_val = 0
            for bit in byte_bits:
                byte_val = (byte_val << 1) | bit
            data.append(byte_val)
        return bytes(data)
    
    def _permute(self, bits, table):
        """Permute bits according to table"""
        return [bits[i-1] for i in table]
    
    def _left_shift(self, bits, n):
        """Left shift bits by n positions"""
        return bits[n:] + bits[:n]
    
    def _generate_subkeys(self):
        """Generate 16 subkeys for DES rounds"""
        # Convert key to bits
        key_bits = self._string_to_bits(self.key)
        
        # Apply PC1
        key_pc1 = self._permute(key_bits, PC1)
        
        # Split into C0 and D0
        C = key_pc1[:28]
        D = key_pc1[28:]
        
        subkeys = []
        
        for round_num in range(16):
            # Shift left
            shift_count = SHIFT[round_num]
            C = self._left_shift(C, shift_count)
            D = self._left_shift(D, shift_count)
            
            # Combine and apply PC2
            combined = C + D
            subkey = self._permute(combined, PC2)
            subkeys.append(subkey)
        
        return subkeys
    
    def _expand(self, bits):
        """Expand 32 bits to 48 bits using E table"""
        return self._permute(bits, E)
    
    def _s_box_substitute(self, bits):
        """Apply S-box substitution"""
        result = []
        # Split into 8 groups of 6 bits
        for i in range(8):
            chunk = bits[i*6:(i+1)*6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            val = S_BOX[i][row][col]
            
            # Convert to 4 bits
            for j in range(3, -1, -1):
                result.append((val >> j) & 1)
        
        return result
    
    def _f_function(self, right, subkey):
        """The f function used in each round"""
        # Expand right half
        expanded = self._expand(right)
        
        # XOR with subkey
        xored = [expanded[i] ^ subkey[i] for i in range(48)]
        
        # S-box substitution
        substituted = self._s_box_substitute(xored)
        
        # Permute with P table
        result = self._permute(substituted, P)
        
        return result
    
    def _process_block(self, block, encrypt=True):
        """Process a single 64-bit block"""
        # Initial permutation
        block = self._permute(block, IP)
        
        # Split into left and right
        left = block[:32]
        right = block[32:]
        
        # 16 rounds
        for round_num in range(16):
            if encrypt:
                subkey = self.subkeys[round_num]
            else:
                subkey = self.subkeys[15 - round_num]
            
            # Save current right
            temp_right = right[:]
            
            # Apply f function
            f_result = self._f_function(temp_right, subkey)
            
            # New right = left XOR f(right, subkey)
            right = [left[i] ^ f_result[i] for i in range(32)]
            
            # New left = old right
            left = temp_right
        
        # Final swap and inverse permutation
        final_block = right + left
        result_block = self._permute(final_block, FP)
        
        return result_block
    
    def _pad_data(self, data):
        """Pad data to multiple of 8 bytes using PKCS#7"""
        padding_len = 8 - (len(data)) % 8
        if padding_len == 0:
            padding_len = 8
        padding = chr(padding_len) * padding_len
        return data + padding
    
    def _unpad_data(self, data):
        """Remove PKCS#7 padding"""
        if not data:
            return data
        padding_len = ord(data[-1])
        # Validate padding
        if padding_len > 8 or padding_len < 1:
            return data
        if data[-padding_len:] == chr(padding_len) * padding_len:
            return data[:-padding_len]
        return data
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using DES"""
        if not plaintext:
            return b""
        
        # Pad the plaintext
        padded_text = self._pad_data(plaintext)
        
        # Convert to bits and process in 64-bit blocks
        encrypted_blocks = []
        
        for i in range(0, len(padded_text), 8):
            block_text = padded_text[i:i+8]
            # Pad last block if needed
            if len(block_text) < 8:
                block_text = block_text.ljust(8, '\x00')
            
            block_bits = self._string_to_bits(block_text)
            encrypted_bits = self._process_block(block_bits, encrypt=True)
            encrypted_blocks.append(encrypted_bits)
        
        # Convert all blocks to bytes
        result_bytes = b''
        for block in encrypted_blocks:
            result_bytes += self._bits_to_bytes(block)
        
        return result_bytes
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using DES"""
        if not ciphertext:
            return ""
        
        # Convert to bits and process in 64-bit blocks
        decrypted_blocks = []
        
        for i in range(0, len(ciphertext), 8):
            block_bytes = ciphertext[i:i+8]
            if len(block_bytes) < 8:
                # Pad with zeros if needed
                block_bytes = block_bytes + b'\x00' * (8 - len(block_bytes))
            
            block_bits = self._bytes_to_bits(block_bytes)
            decrypted_bits = self._process_block(block_bits, encrypt=False)
            decrypted_blocks.append(decrypted_bits)
        
        # Convert all blocks to string
        result_text = ''
        for block in decrypted_blocks:
            result_text += self._bits_to_string(block)
        
        # Remove padding
        result_text = self._unpad_data(result_text)
        
        return result_text

def main():
    print("DES Encryption/Decryption Program")
    print("=" * 40)
    test_des()
    
    # Use a fixed key for testing
    key = "12345678"
    des = DES(key)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt text")
        print("2. Decrypt text") 
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == '1':
            plaintext = input("Enter text to encrypt: ").strip()
            if not plaintext:
                print("Error: No text entered")
                continue
                
            try:
                ciphertext = des.encrypt(plaintext)
                hex_cipher = binascii.hexlify(ciphertext).decode()
                print(f"\nOriginal text: {plaintext}")
                print(f"Encrypted (hex): {hex_cipher}")
                print(f"Key used: {key}")
            except Exception as e:
                print(f"Encryption error: {e}")
                
        elif choice == '2':
            hex_input = input("Enter encrypted hex string: ").strip()
            if not hex_input:
                print("Error: No hex string entered")
                continue
                
            try:
                ciphertext = binascii.unhexlify(hex_input)
                plaintext = des.decrypt(ciphertext)
                print(f"\nDecrypted text: {plaintext}")
            except Exception as e:
                print(f"Decryption error: {e}")
                
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

def test_des():
    """Test the DES implementation"""
    print("Testing DES Implementation...")
    print("=" * 30)
    
    test_cases = [
        "Hello",
        "Hide the gold", 
        "DES",
        "A",  # Single character
        "1234567890",  # Numbers
        "Test with spaces",
    ]
    
    key = "12345678"
    des = DES(key)
    
    for i, test_text in enumerate(test_cases, 1):
        print(f"\nTest {i}: '{test_text}'")
        
        try:
            # Encrypt
            ciphertext = des.encrypt(test_text)
            hex_cipher = binascii.hexlify(ciphertext).decode()
            print(f"  Encrypted: {hex_cipher}")
            
            # Decrypt  
            decrypted = des.decrypt(ciphertext)
            print(f"  Decrypted: '{decrypted}'")
            
            # Verify
            if test_text == decrypted:
                print("  ✓ SUCCESS")
            else:
                print("  ✗ FAILED")
                print(f"    Expected: '{test_text}'")
                print(f"    Got: '{decrypted}'")
                
        except Exception as e:
            print(f"  ✗ ERROR: {e}")

if __name__ == "__main__":
    # Run tests first
    test_des()
    print("\n" + "=" * 50)
    
    # Then run main program
    main()