"""
Enhanced cryptography module with RSA-PSS signing and AES-GCM encryption
(ĐÃ NÂNG CẤP: Thêm logic tạo Self-Signed Certificate X.509)
"""
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
from typing import Tuple, Optional
from datetime import datetime, timedelta

# Import X.509 cho certificate
from cryptography import x509
from cryptography.x509.oid import NameOID


class CryptoManager:
    """Manages cryptographic operations for contract signing"""
    
    KEY_SIZE = 2048
    AES_KEY_SIZE = 32  # 256 bits
    
    @staticmethod
    def generate_self_signed_cert_and_key(key_name: str, password: Optional[str] = None) -> Tuple[bytes, bytes, bytes]:
        """
        NÂNG CẤP: Tạo cặp key RSA VÀ một certificate tự ký (self-signed)
        
        Args:
            key_name (str): Tên của key, sẽ dùng làm "Common Name" (CN) cho certificate.
            password (Optional[str]): Mật khẩu để mã hóa private key.
            
        Returns:
            Tuple of (private_key_pem, public_key_pem, certificate_pem)
        """
        
        # 1. Tạo private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CryptoManager.KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # 2. Tạo thông tin cho certificate (Subject/Issuer)
        # Vì đây là self-signed, Subject (chủ thể) và Issuer (người phát hành) là một
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hanoi"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hanoi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Self-Signed CA"),
            # Dùng key_name làm Common Name (CN)
            x509.NameAttribute(NameOID.COMMON_NAME, key_name),
        ])

        # 3. Bắt đầu xây dựng certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow() - timedelta(days=1) # Có hiệu lực từ hôm qua
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=5*365) # Hiệu lực 5 năm
        ).add_extension( # Thêm các extension cơ bản
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), # Đây là cert của người dùng (end-entity), không phải CA
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True, 
                content_commitment=True, # Quan trọng cho ký PDF (non-repudiation)
                key_encipherment=False, 
                data_encipherment=False, 
                key_agreement=False, 
                key_cert_sign=False, 
                crl_sign=False, 
                encipher_only=False, 
                decipher_only=False
            ),
            critical=True
        )

        # 4. Ký certificate (bằng chính private key của nó)
        certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

        # 5. Mã hóa private key nếu có password
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
            
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        # 6. Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 7. Serialize certificate
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

        return private_pem, public_pem, certificate_pem

    # ------------------------------------------------------------------
    # CÁC HÀM CŨ VẪN GIỮ NGUYÊN
    # ------------------------------------------------------------------

    @staticmethod
    def generate_key_pair(password: Optional[str] = None) -> Tuple[bytes, bytes]:
        """
        Hàm này (cũ) giờ không dùng nữa, nhưng giữ lại phòng trường hợp khác cần.
        Dùng generate_self_signed_cert_and_key thay thế.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=CryptoManager.KEY_SIZE,
            backend=default_backend()
        )
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    @staticmethod
    def encrypt_private_key(private_key_pem: bytes, user_password: str) -> Tuple[bytes, bytes, bytes]:
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', user_password.encode(), salt, 100000, dklen=32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, private_key_pem, None)
        return encrypted_data, salt, nonce
    
    @staticmethod
    def decrypt_private_key(encrypted_data: bytes, salt: bytes, nonce: bytes, user_password: str) -> bytes:
        key = hashlib.pbkdf2_hmac('sha256', user_password.encode(), salt, 100000, dklen=32)
        aesgcm = AESGCM(key)
        private_key_pem = aesgcm.decrypt(nonce, encrypted_data, None)
        return private_key_pem
    
    @staticmethod
    def hash_document(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()
    
    @staticmethod
    def sign_document(content: bytes, private_key_pem: bytes, password: Optional[str] = None) -> str:
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
        document_hash = hashlib.sha256(content).digest()
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
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            signature = base64.b64decode(signature_b64)
            document_hash = hashlib.sha256(content).digest()
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
        # Dùng SHA1 cho fingerprint ngắn gọn, dễ nhìn, theo chuẩn chung
        # Hoặc dùng SHA256 nếu bạn muốn
        return hashlib.sha1(public_key_pem).hexdigest()[:16].upper()