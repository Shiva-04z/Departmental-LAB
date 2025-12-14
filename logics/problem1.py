# caesar_cipher.py

def encrypt(text, shift):
    """Encrypts the given text using the Caesar Cipher."""
    result = ""

    for char in text:
        if char.isalpha():  # Only encrypt letters
            base = ord('A') if char.isupper() else ord('a')
            # Shift character and wrap around using modulo
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            # Non-alphabetical characters remain unchanged
            result += char
    return result

def decrypt(text, shift):
    """Decrypts the given text using the Caesar Cipher."""
    return encrypt(text, -shift)

def main():
    print("=== Caesar Cipher Program ===")
    text = input("Enter text: ")
    shift = int(input("Enter shift value (e.g., 3): "))

    encrypted = encrypt(text, shift)
    decrypted = decrypt(encrypted, shift)

    print(f"\nEncrypted Text: {encrypted}")
    print(f"Decrypted Text: {decrypted}")


if __name__ == "__main__":
    main()
