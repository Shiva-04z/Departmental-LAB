import hashlib
import random
import secrets
from typing import Tuple, Optional

class EllipticCurve:
    """
    Elliptic Curve implementation for ECDSA
    Using secp256k1 parameters (same as Bitcoin)
    """
    
    def __init__(self):
        # secp256k1 parameters
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0
        self.b = 7
        self.G = (
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.h = 1  # cofactor
    
    def is_on_curve(self, point: Tuple[int, int]) -> bool:
        """
        Check if a point is on the elliptic curve
        """
        if point is None:
            return True
        
        x, y = point
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0
    
    def point_add(self, P1: Tuple[int, int], P2: Tuple[int, int]) -> Tuple[int, int]:
        """
        Add two points on the elliptic curve
        """
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        
        x1, y1 = P1
        x2, y2 = P2
        
        if x1 == x2:
            if y1 != y2:
                return None  # P1 + (-P1) = infinity
            elif y1 == 0:
                return None  # P1 is point at infinity
            else:
                # Point doubling
                s = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else:
            s = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        
        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        
        return (x3, y3)
    
    def point_multiply(self, k: int, point: Tuple[int, int]) -> Tuple[int, int]:
        """
        Multiply a point by a scalar (elliptic curve multiplication)
        """
        if k % self.n == 0 or point is None:
            return None
        
        if k < 0:
            return self.point_multiply(-k, self.point_negate(point))
        
        result = None
        addend = point
        
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        
        return result
    
    def point_negate(self, point: Tuple[int, int]) -> Tuple[int, int]:
        """
        Negate a point (find its inverse)
        """
        if point is None:
            return None
        
        x, y = point
        return (x, (-y) % self.p)


class ECDSA:
    """
    ECDSA (Elliptic Curve Digital Signature Algorithm) implementation
    """
    
    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or EllipticCurve()
    
    def generate_key_pair(self) -> Tuple[int, Tuple[int, int]]:
        """
        Generate ECDSA key pair
        
        Returns:
            Tuple of (private_key, public_key)
            private_key: integer (d)
            public_key: curve point (Q)
        """
        # Generate private key (random number in [1, n-1])
        private_key = secrets.randbelow(self.curve.n - 1) + 1
        
        # Generate public key: Q = d * G
        public_key = self.curve.point_multiply(private_key, self.curve.G)
        
        if not self.curve.is_on_curve(public_key):
            raise ValueError("Generated public key is not on the curve")
        
        return private_key, public_key
    
    def hash_message(self, message: str) -> int:
        """
        Hash the message using SHA-256 and convert to integer
        
        Args:
            message: The message to hash
            
        Returns:
            Integer representation of the hash
        """
        message_bytes = message.encode('utf-8')
        hash_bytes = hashlib.sha256(message_bytes).digest()
        hash_int = int.from_bytes(hash_bytes, 'big')
        
        # Reduce hash to curve order
        return hash_int % self.curve.n
    
    def sign_message(self, message: str, private_key: int) -> Tuple[int, int]:
        """
        Create ECDSA signature for a message
        
        Args:
            message: The message to sign
            private_key: Private key for signing
            
        Returns:
            Tuple of (r, s) - the ECDSA signature components
        """
        if private_key >= self.curve.n or private_key < 1:
            raise ValueError("Invalid private key")
        
        message_hash = self.hash_message(message)
        
        while True:
            # Generate ephemeral key k
            k = secrets.randbelow(self.curve.n - 1) + 1
            
            # Calculate r = (k * G).x mod n
            R = self.curve.point_multiply(k, self.curve.G)
            r = R[0] % self.curve.n
            
            if r == 0:
                continue  # Try again if r is 0
            
            # Calculate s = k^(-1) * (hash + r * private_key) mod n
            k_inv = pow(k, -1, self.curve.n)
            s = (k_inv * (message_hash + r * private_key)) % self.curve.n
            
            if s == 0:
                continue  # Try again if s is 0
            
            break
        
        return r, s
    
    def verify_signature(self, message: str, signature: Tuple[int, int], public_key: Tuple[int, int]) -> bool:
        """
        Verify ECDSA signature for a message
        
        Args:
            message: The original message
            signature: Tuple (r, s) - the ECDSA signature
            public_key: Public key for verification
            
        Returns:
            True if signature is valid, False otherwise
        """
        r, s = signature
        
        # Validate signature components
        if r < 1 or r >= self.curve.n or s < 1 or s >= self.curve.n:
            return False
        
        # Validate public key
        if not self.curve.is_on_curve(public_key):
            return False
        
        message_hash = self.hash_message(message)
        
        # Calculate w = s^(-1) mod n
        w = pow(s, -1, self.curve.n)
        
        # Calculate u1 = hash * w mod n
        u1 = (message_hash * w) % self.curve.n
        
        # Calculate u2 = r * w mod n
        u2 = (r * w) % self.curve.n
        
        # Calculate point = u1 * G + u2 * Q
        point1 = self.curve.point_multiply(u1, self.curve.G)
        point2 = self.curve.point_multiply(u2, public_key)
        point = self.curve.point_add(point1, point2)
        
        if point is None:
            return False
        
        # Signature is valid if point.x mod n == r
        return point[0] % self.curve.n == r
    
    def signature_to_string(self, signature: Tuple[int, int]) -> str:
        """
        Convert signature to string representation
        """
        r, s = signature
        return f"r: {r:064x}\ns: {s:064x}"
    
    def public_key_to_string(self, public_key: Tuple[int, int]) -> str:
        """
        Convert public key to string representation
        """
        x, y = public_key
        return f"x: {x:064x}\ny: {y:064x}"





def interactive_mode():
    """Interactive mode for ECDSA operations"""
    print(f"\nInteractive ECDSA System")
    print("=" * 40)
    
    ecdsa = ECDSA()
    private_key = None
    public_key = None
    
    while True:
        print(f"\nOptions:")
        print("1. Generate new key pair")
        print("2. Sign a message")
        print("3. Verify a signature")
        print("4. Show current public key")
        print("5. Exit")
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == '1':
            private_key, public_key = ecdsa.generate_key_pair()
            print(f"New key pair generated!")
            print(f"Private key: {private_key:064x}")
            print(f"Public key:\n{ecdsa.public_key_to_string(public_key)}")
        
        elif choice == '2':
            if private_key is None:
                print("Please generate a key pair first!")
                continue
            
            message = input("Enter message to sign: ")
            
            try:
                signature = ecdsa.sign_message(message, private_key)
                print(f"Message: '{message}'")
                print(f"Signature:\n{ecdsa.signature_to_string(signature)}")
                
                # Verify immediately to demonstrate
                is_valid = ecdsa.verify_signature(message, signature, public_key)
                print(f"Immediate Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
                
            except Exception as e:
                print(f"Error during signing: {e}")
        
        elif choice == '3':
            if public_key is None:
                print("Please generate a key pair first!")
                continue
            
            message = input("Enter original message: ")
            try:
                r_hex = input("Enter r component (hex): ").strip()
                s_hex = input("Enter s component (hex): ").strip()
                r = int(r_hex, 16)
                s = int(s_hex, 16)
                signature = (r, s)
            except ValueError:
                print("Invalid signature format. Please enter valid hexadecimal numbers.")
                continue
            
            try:
                is_valid = ecdsa.verify_signature(message, signature, public_key)
                print(f"\nVerification Result: {'✓ SIGNATURE IS VALID' if is_valid else '✗ SIGNATURE IS INVALID'}")
                print(f"Message: '{message}'")
                print(f"Provided Signature: r={r:064x}, s={s:064x}")
                
            except Exception as e:
                print(f"Error during verification: {e}")
        
        elif choice == '4':
            if public_key is None:
                print("No public key available. Generate a key pair first.")
            else:
                print(f"Current Public Key:\n{ecdsa.public_key_to_string(public_key)}")
        
        elif choice == '5':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")





if __name__ == "__main__":
  
    # Start interactive mode
    interactive_mode()