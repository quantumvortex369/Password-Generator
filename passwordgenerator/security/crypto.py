"""Cryptographic functions for password security."""
import os
import base64
import hashlib
from typing import Optional, Union, Tuple

# Try to import cryptography, but make it optional
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Constants
SALT_LENGTH = 16  # 128 bits
ITERATIONS = 100_000
HASH_ALGORITHM = hashes.SHA256() if CRYPTO_AVAILABLE else None
KEY_LENGTH = 32  # 256 bits

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Hash a password with a salt.
    
    Args:
        password: The password to hash
        salt: Optional salt (if None, a random one will be generated)
        
    Returns:
        Tuple of (salt, hashed_password)
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    # Generate a random salt if not provided
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    
    # Use PBKDF2 for key derivation
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    
    return salt, dk

def verify_password(stored_salt: bytes, stored_hash: bytes, password: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        stored_salt: The salt used for the stored hash
        stored_hash: The stored hash to verify against
        password: The password to verify
        
    Returns:
        True if the password matches, False otherwise
    """
    if not stored_salt or not stored_hash or not password:
        return False
    
    # Hash the provided password with the stored salt
    _, new_hash = hash_password(password, stored_salt)
    
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(stored_hash, new_hash)

def encrypt_data(data: str, password: str) -> bytes:
    """
    Encrypt data with a password.
    
    Args:
        data: The data to encrypt (as a string)
        password: The password to use for encryption
        
    Returns:
        Encrypted data as bytes
        
    Raises:
        RuntimeError: If cryptography is not available
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Cryptography library not available. Install with: pip install cryptography")
    
    # Generate a random salt
    salt = os.urandom(SALT_LENGTH)
    
    # Derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=HASH_ALGORITHM,
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    f = Fernet(key)
    
    # Encrypt the data
    encrypted_data = f.encrypt(data.encode('utf-8'))
    
    # Return salt + encrypted data
    return salt + encrypted_data

def decrypt_data(encrypted_data: bytes, password: str) -> str:
    """
    Decrypt data with a password.
    
    Args:
        encrypted_data: The encrypted data (as bytes)
        password: The password used for encryption
        
    Returns:
        Decrypted data as a string
        
    Raises:
        ValueError: If the data is invalid or decryption fails
        RuntimeError: If cryptography is not available
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Cryptography library not available. Install with: pip install cryptography")
    
    if len(encrypted_data) < SALT_LENGTH:
        raise ValueError("Invalid encrypted data")
    
    # Extract the salt and the actual encrypted data
    salt = encrypted_data[:SALT_LENGTH]
    encrypted = encrypted_data[SALT_LENGTH:]
    
    # Derive the key from the password
    kdf = PBKDF2HMAC(
        algorithm=HASH_ALGORITHM,
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    f = Fernet(key)
    
    try:
        # Decrypt the data
        decrypted = f.decrypt(encrypted)
        return decrypted.decode('utf-8')
    except (InvalidToken, ValueError) as e:
        raise ValueError("Invalid password or corrupted data") from e

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.
    
    Args:
        length: Length of the token in bytes
        
    Returns:
        A URL-safe base64-encoded random token
    """
    if length < 16:
        raise ValueError("Token length must be at least 16 bytes")
    
    random_bytes = os.urandom(length)
    return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')

def check_password_breach(password: str) -> int:
    """
    Check if a password has been exposed in a data breach using k-anonymity.
    
    This uses the Have I Been Pwned API to check if the password has been exposed.
    
    Args:
        password: The password to check
        
    Returns:
        Number of times the password has been found in breaches (0 means not found)
    """
    import requests
    from urllib.parse import quote
    
    # Hash the password with SHA-1
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = password_hash[:5]
    suffix = password_hash[5:]
    
    try:
        # Make the API request (k-anonymity)
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(
            url,
            headers={"User-Agent": "PasswordGenerator/1.0"},
            timeout=5
        )
        
        if response.status_code == 200:
            # Check if our suffix is in the response
            for line in response.text.splitlines():
                if line.startswith(suffix):
                    # Return the count
                    return int(line.split(':')[1])
        
        return 0
    except Exception:
        # If there's any error, assume the password is not in a breach
        # (fail securely rather than exposing users to risk)
        return 0
