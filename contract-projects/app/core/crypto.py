"""
Enhanced cryptography module with RSA-PSS signing and AES-GCM encryption
"""
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
from typing import Tuple, Optional


class CryptoManager:
    """Manages cryptographic operations for contract signing"""
    
    # RSA key size (2048 or 4096 for production)
    KEY_SIZE = 2048
    
    # AES-GCM key size
    AES_KEY_SIZE = 32  # 256 bits
    
    @staticmethod
    def generate_key_pair(password: Optional[str] = None) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair
        
        Args:
            password: Optional password to encrypt private key
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CryptoManager.KEY_SIZE,
            backend=default_backend()
        )
        
        # Serialize private key
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
            
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def encrypt_private_key(private_key_pem: bytes, user_password: str) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt private key using AES-GCM with user password
        
        Args:
            private_key_pem: PEM-encoded private key
            user_password: User's password for key derivation
            
        Returns:
            Tuple of (encrypted_data, salt, nonce)
        """
        # Generate salt
        salt = os.urandom(16)
        
        # Derive key from password using PBKDF2
        key = hashlib.pbkdf2_hmac('sha256', user_password.encode(), salt, 100000, dklen=32)
        
        # Generate nonce
        nonce = os.urandom(12)
        
        # Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, private_key_pem, None)
        
        return encrypted_data, salt, nonce
    
    @staticmethod
    def decrypt_private_key(encrypted_data: bytes, salt: bytes, nonce: bytes, user_password: str) -> bytes:
        """
        Decrypt private key using AES-GCM
        
        Args:
            encrypted_data: Encrypted private key
            salt: Salt used for key derivation
            nonce: Nonce used for encryption
            user_password: User's password
            
        Returns:
            Decrypted private key PEM
        """
        # Derive key from password
        key = hashlib.pbkdf2_hmac('sha256', user_password.encode(), salt, 100000, dklen=32)
        
        # Decrypt
        aesgcm = AESGCM(key)
        private_key_pem = aesgcm.decrypt(nonce, encrypted_data, None)
        
        return private_key_pem
    
    @staticmethod
    def hash_document(content: bytes) -> str:
        """
        Calculate SHA-256 hash of document
        
        Args:
            content: Document content in bytes
            
        Returns:
            Hex string of hash
        """
        return hashlib.sha256(content).hexdigest()
    
    @staticmethod
    def sign_document(content: bytes, private_key_pem: bytes, password: Optional[str] = None) -> str:
        """
        Sign document using RSA-PSS
        
        Args:
            content: Document content
            private_key_pem: PEM-encoded private key
            password: Password if private key is encrypted
            
        Returns:
            Base64-encoded signature
        """
        # Load private key
        if password:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode(),
                backend=default_backend()
            )
        else:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
        
        # Calculate hash
        document_hash = hashlib.sha256(content).digest()
        
        # Sign using RSA-PSS
        signature = private_key.sign(
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def verify_signature(content: bytes, signature_b64: str, public_key_pem: bytes) -> bool:
        """
        Verify document signature using RSA-PSS
        
        Args:
            content: Document content
            signature_b64: Base64-encoded signature
            public_key_pem: PEM-encoded public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Calculate hash
            document_hash = hashlib.sha256(content).digest()
            
            # Verify signature
            public_key.verify(
                signature,
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    @staticmethod
    def get_key_fingerprint(public_key_pem: bytes) -> str:
        """
        Generate fingerprint for public key
        
        Args:
            public_key_pem: PEM-encoded public key
            
        Returns:
            Hex string fingerprint
        """
        return hashlib.sha256(public_key_pem).hexdigest()[:16]


# Convenience functions
def generate_keys(password: Optional[str] = None) -> Tuple[bytes, bytes]:
    """Generate RSA key pair"""
    return CryptoManager.generate_key_pair(password)


def hash_file(content: bytes) -> str:
    """Hash file content"""
    return CryptoManager.hash_document(content)


def sign_file(content: bytes, private_key: bytes, password: Optional[str] = None) -> str:
    """Sign file content"""
    return CryptoManager.sign_document(content, private_key, password)


def verify_file(content: bytes, signature: str, public_key: bytes) -> bool:
    """Verify file signature"""
    return CryptoManager.verify_signature(content, signature, public_key)