# playfair_cipher.py
# Program to implement the Playfair Cipher (Digraph encryption)

def generate_key_matrix(key):
    """Generates a 5x5 matrix for the Playfair cipher using the given key."""
    key = key.upper().replace("J", "I")  # 'I' and 'J' are considered the same
    matrix = []
    used = set()

    # Add key letters
    for char in key:
        if char.isalpha() and char not in used:
            matrix.append(char)
            used.add(char)

    # Add remaining letters
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # J excluded
        if char not in used:
            matrix.append(char)
            used.add(char)

    # Return as 5x5 matrix
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def format_text(text):
    """Prepare text for Playfair encryption: remove spaces, handle duplicates."""
    text = text.upper().replace("J", "I").replace(" ", "")
    formatted = ""
    i = 0
    while i < len(text):
        char1 = text[i]
        char2 = text[i + 1] if i + 1 < len(text) else 'X'

        if char1 == char2:
            formatted += char1 + 'X'
            i += 1
        else:
            formatted += char1 + char2
            i += 2

    if len(formatted) % 2 != 0:
        formatted += 'X'
    return formatted


def find_position(matrix, letter):
    """Find the (row, column) of a letter in the matrix."""
    for i, row in enumerate(matrix):
        if letter in row:
            return i, row.index(letter)
    return None


def encrypt_pair(pair, matrix):
    """Encrypts a pair of letters according to Playfair rules."""
    r1, c1 = find_position(matrix, pair[0])
    r2, c2 = find_position(matrix, pair[1])

    # Same row
    if r1 == r2:
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]

    # Same column
    elif c1 == c2:
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]

    # Rectangle rule
    else:
        return matrix[r1][c2] + matrix[r2][c1]


def decrypt_pair(pair, matrix):
    """Decrypts a pair of letters according to Playfair rules."""
    r1, c1 = find_position(matrix, pair[0])
    r2, c2 = find_position(matrix, pair[1])

    # Same row
    if r1 == r2:
        return matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]

    # Same column
    elif c1 == c2:
        return matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]

    # Rectangle rule
    else:
        return matrix[r1][c2] + matrix[r2][c1]


def encrypt(text, key):
    matrix = generate_key_matrix(key)
    formatted = format_text(text)
    ciphertext = ""

    for i in range(0, len(formatted), 2):
        ciphertext += encrypt_pair(formatted[i:i+2], matrix)
    return ciphertext


def decrypt(text, key):
    matrix = generate_key_matrix(key)
    plaintext = ""

    for i in range(0, len(text), 2):
        plaintext += decrypt_pair(text[i:i+2], matrix)
    return plaintext


def main():
    print("=== Playfair Cipher ===")
    text = input("Enter text: ")
    key = input("Enter key: ")

    encrypted = encrypt(text, key)
    decrypted = decrypt(encrypted, key)

    print("\nGenerated 5x5 Matrix:")
    for row in generate_key_matrix(key):
        print(row)

    print(f"\nFormatted Text: {format_text(text)}")
    print(f"Encrypted Text: {encrypted}")
    print(f"Decrypted Text: {decrypted}")


if __name__ == "__main__":
    main()
