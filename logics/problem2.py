def encrypt(plaintext, key):
    """Encrypts the plaintext using the Vigenère cipher."""
    ciphertext = ""
    key = key.upper()
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            ciphertext += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            ciphertext += char  
    return ciphertext


def decrypt(ciphertext, key):
    """Decrypts the ciphertext using the Vigenère cipher."""
    plaintext = ""
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            plaintext += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            plaintext += char
    return plaintext


def main():
    print("=== Polyalphabetic Substitution (Vigenère Cipher) ===")
    text = input("Enter text: ")
    key = input("Enter key (letters only): ")
    encrypted = encrypt(text, key)
    decrypted = decrypt(encrypted, key)
    print(f"\nEncrypted Text: {encrypted}")
    print(f"Decrypted Text: {decrypted}")


if __name__ == "__main__":
    main()





