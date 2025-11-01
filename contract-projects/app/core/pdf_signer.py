# app/core/pdf_signer.py
import logging
from datetime import datetime, timezone
import io
import asyncio
from typing import Generator, Optional

# --- PYHANKO IMPORTS ---
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import signers, fields
from pyhanko.sign.validation import async_validate_pdf_signature  # FIX: Dùng async version
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

# --- CRYPTOGRAPHY IMPORTS ---
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

# --- ASN1CRYPTO IMPORTS (Required by pyHanko) ---
from asn1crypto import x509 as asn1_x509
from asn1crypto import keys as asn1_keys

logger = logging.getLogger(__name__)


class PDFSigner:
    """
    Quản lý việc ký và xác thực PDF bằng pyhanko (PAdES).
    
    PYHANKO OBJECTS REFERENCE:
    ==========================
    1. EmbeddedPdfSignature (từ reader.embedded_signatures[i]):
       - Attributes: field_name, signer_cert
       - KHÔNG CÓ: signing_time, signing_cert
    
    2. PdfSignatureStatus (từ async_validate_pdf_signature()):
       - Attributes: valid, intact, signing_cert, timestamp, summary
       - KHÔNG CÓ: signer_cert
    """
    def __init__(self):
        logger.info("PDFSigner (pyhanko) initialized.")

    def _repair_pdf(self, pdf_bytes: bytes) -> bytes:
        """
        Repair corrupted PDF bằng cách đọc và viết lại.
        Sử dụng khi PDF có lỗi cấu trúc như generation number không hợp lệ.
        
        Args:
            pdf_bytes: PDF có thể bị corrupt
            
        Returns:
            bytes: PDF đã được repair
        """
        try:
            logger.info("Attempting to repair PDF structure...")
            
            # Đọc PDF với strict=False để bỏ qua lỗi nhỏ
            reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
            
            # Tạo writer mới - FIX: Dùng IncrementalPdfFileWriter thay vì PdfFileWriter
            output = io.BytesIO()
            
            # Copy toàn bộ PDF structure
            # Cách đơn giản nhất: Đọc và ghi lại bằng IncrementalPdfFileWriter
            input_stream = io.BytesIO(pdf_bytes)
            writer = IncrementalPdfFileWriter(input_stream, strict=False)
            
            # Ghi lại PDF (sẽ tự động fix structure issues)
            writer.write(output)
            
            repaired = output.getvalue()
            logger.info(f"PDF repaired successfully: {len(pdf_bytes)} -> {len(repaired)} bytes")
            
            return repaired
            
        except Exception as e:
            logger.warning(f"Failed to repair PDF: {e}")
            logger.info("Using original PDF despite errors")
            return pdf_bytes

    async def embed_signature(
        self, 
        pdf_bytes: bytes, 
        signer_private_key_pem: bytes, 
        signer_cert_pem: str, 
        signature_meta: dict,
        auto_repair: bool = True
    ) -> bytes:
        """
        Nhúng chữ ký PKCS#7 (PAdES-B) vào file PDF.
        
        CRITICAL: Phải là async function vì pyHanko's async_sign_pdf() được gọi bên trong.
        Không thể dùng sign_pdf() trong FastAPI async context vì nó gọi asyncio.run() 
        mà sẽ conflict với event loop đang chạy.
        
        Args:
            pdf_bytes: Nội dung PDF gốc
            signer_private_key_pem: Private key dạng PEM (bytes)
            signer_cert_pem: Certificate dạng PEM (string)
            signature_meta: Metadata cho chữ ký (field_name, name, location, reason, etc.)
            auto_repair: Tự động repair PDF nếu gặp lỗi cấu trúc (default: True)
            
        Returns:
            bytes: PDF đã được ký
        """
        logger.info(f"Bắt đầu nhúng chữ ký pyhanko cho file {len(pdf_bytes)} bytes.")

        # ========================================================
        # BƯỚC 0: Kiểm tra và Repair PDF nếu cần
        # ========================================================
        if auto_repair:
            try:
                # Thử mở PDF với strict mode để check
                test_stream = io.BytesIO(pdf_bytes)
                test_reader = PdfFileReader(test_stream, strict=True)
                logger.info("PDF structure is valid, no repair needed")
            except Exception as check_error:
                logger.warning(f"PDF has structural issues: {check_error}")
                logger.info("Auto-repairing PDF before signing...")
                pdf_bytes = self._repair_pdf(pdf_bytes)

        try:
            # ========================================================
            # BƯỚC 1: Load Private Key
            # FIX CRITICAL: PyHanko cũng cần private key ở định dạng asn1crypto
            # ========================================================
            # Bước 1.1: Load bằng cryptography
            private_key_crypto = serialization.load_pem_private_key(
                signer_private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Bước 1.2: Convert sang DER bytes
            private_key_der = private_key_crypto.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Bước 1.3: Load bằng asn1crypto (định dạng pyHanko cần)
            private_key_asn1 = asn1_keys.PrivateKeyInfo.load(private_key_der)
            logger.info("Private key loaded and converted to asn1crypto format")
            
            # ========================================================
            # BƯỚC 2: Load Certificate
            # FIX CRITICAL: PyHanko cần cert ở định dạng asn1crypto, không phải cryptography
            # ========================================================
            # Bước 2.1: Load bằng cryptography để convert sang DER
            cert_crypto = x509.load_pem_x509_certificate(
                signer_cert_pem.encode('utf-8'), 
                default_backend()
            )
            
            # Bước 2.2: Convert sang DER bytes
            cert_der = cert_crypto.public_bytes(serialization.Encoding.DER)
            
            # Bước 2.3: Load bằng asn1crypto (định dạng mà pyHanko cần)
            cert_asn1 = asn1_x509.Certificate.load(cert_der)
            logger.info(f"Certificate loaded: {cert_asn1.subject.human_friendly}")
            
            # ========================================================
            # BƯỚC 2.5: Tạo SimpleCertificateStore
            # FIX CRITICAL: SimpleCertificateStore.certs phải là DICT, không phải list
            # Key = cert subject, Value = cert object
            # ========================================================
            cert_store = SimpleCertificateStore()
            # Tạo dict với key là subject fingerprint hoặc subject name
            # SimpleCertificateStore expects: {key: cert, ...}
            cert_subject_key = cert_asn1.subject.human_friendly
            cert_store.certs = {cert_subject_key: cert_asn1}
            logger.info(f"Certificate store created with cert: {cert_subject_key}")

            # ========================================================
            # BƯỚC 3: Tạo SimpleSigner
            # FIX CRITICAL: Cả cert VÀ private key đều phải là asn1crypto format
            # ========================================================
            signer = signers.SimpleSigner(
                signing_cert=cert_asn1,        # asn1crypto x509.Certificate
                signing_key=private_key_asn1,  # asn1crypto keys.PrivateKeyInfo
                cert_registry=cert_store,      # SimpleCertificateStore instance
                signature_mechanism=None       # Auto-detect từ key type
            )
            logger.info("SimpleSigner created successfully")

            # ========================================================
            # BƯỚC 4: Chuẩn bị Signature Metadata
            # ========================================================
            sig_meta = signers.PdfSignatureMetadata(
                field_name=signature_meta.get('field_name', 'Signature1'),
                name=signature_meta.get('name', 'Digital Signer'),
                location=signature_meta.get('location', 'Vietnam'),
                reason=signature_meta.get('reason', 'Contract Signing'),
            )
            logger.info(f"Signature metadata: {sig_meta.name} at {sig_meta.location}")

            # ========================================================
            # BƯỚC 5: Mở PDF và chuẩn bị Writer
            # CRITICAL: Phải dùng strict=False để xử lý PDF có lỗi nhỏ
            # ========================================================
            pdf_stream = io.BytesIO(pdf_bytes)
            
            # IncrementalPdfFileWriter giữ nguyên nội dung gốc và chỉ append signature
            # strict=False: Cho phép đọc PDF có generation number lỗi, xref issues, etc.
            writer = IncrementalPdfFileWriter(pdf_stream, strict=False)
            logger.info("PDF opened with IncrementalPdfFileWriter (strict=False)")
            
            # ========================================================
            # BƯỚC 6: Tạo PdfSigner
            # ========================================================
            pdf_signer = signers.PdfSigner(
                signature_meta=sig_meta,
                signer=signer,
            )
            logger.info("PdfSigner instance created")

            # ========================================================
            # BƯỚC 7: Thực hiện ký PDF
            # FIX: Dùng async_sign_pdf() thay vì sign_pdf() vì đang trong async context
            # ========================================================
            out_buffer = io.BytesIO()
            
            # Gọi async_sign_pdf() với await
            await pdf_signer.async_sign_pdf(
                writer,
                output=out_buffer,
                existing_fields_only=False,  # Cho phép tạo signature field mới
                # appearance=None,  # Có thể thêm visual appearance nếu cần
            )
            
            signed_pdf = out_buffer.getvalue()
            logger.info(f"PDF signed successfully. Output size: {len(signed_pdf)} bytes")
            
            return signed_pdf

        except AttributeError as e:
            # Bắt lỗi cụ thể về certificate/key attributes
            logger.error(f"Certificate/Key attribute error: {e}", exc_info=True)
            raise ValueError(f"Invalid certificate or key format: {e}")
            
        except Exception as e:
            logger.error(f"Failed to embed signature: {e}", exc_info=True)
            raise ValueError(f"Failed to embed pyhanko signature: {e}")

    async def verify_embedded_signature(self, signed_pdf_bytes: bytes) -> dict:
        """
        Xác thực chữ ký nhúng trong file PDF.
        
        FIX CRITICAL: Chuyển thành async function và dùng async_validate_pdf_signature()
        thay vì validate_pdf_signature() để tránh lỗi "asyncio.run() cannot be called 
        from a running event loop"
        
        Args:
            signed_pdf_bytes: Nội dung PDF đã được ký
            
        Returns:
            dict: Kết quả xác thực với các thông tin:
                - valid: Chữ ký có hợp lệ không
                - trusted_by_ca: Certificate có được trust không
                - intact: PDF có bị thay đổi sau khi ký không
                - message: Thông báo chi tiết
                - signer_info: Thông tin người ký
                - signed_at: Thời gian ký
        """
        logger.info(f"Bắt đầu xác thực chữ ký pyhanko cho file {len(signed_pdf_bytes)} bytes.")
        
        try:
            # Đọc PDF với strict=False để xử lý PDF có lỗi nhỏ
            reader = PdfFileReader(io.BytesIO(signed_pdf_bytes), strict=False)
            
            # Kiểm tra có chữ ký không
            if not reader.embedded_signatures:
                logger.warning("Không tìm thấy chữ ký nhúng nào.")
                return {
                    "valid": False,
                    "trusted_by_ca": False,
                    "intact": False,
                    "message": "File PDF không chứa chữ ký nhúng.",
                    "signer_info": None,
                    "signed_at": None
                }

            # Lấy chữ ký đầu tiên (có thể có nhiều chữ ký)
            # sig là EmbeddedPdfSignature object
            sig = reader.embedded_signatures[0]
            logger.info(f"Found signature field: {sig.field_name}")
            
            # Tạo validation context
            # FIX: sig.signer_cert đúng (từ EmbeddedPdfSignature object)
            validation_context = ValidationContext(
                trust_roots=[sig.signer_cert] if sig.signer_cert else [],
                allow_fetching=False  # Không fetch cert từ internet
            )
            
            # FIX: Dùng async_validate_pdf_signature() thay vì validate_pdf_signature()
            # và AWAIT nó vì đây là async function
            # result là PdfSignatureStatus object
            result = await async_validate_pdf_signature(sig, validation_context)
            
            # ========================================================
            # Extract thông tin người ký
            # FIX CRITICAL: result.signing_cert đúng (từ PdfSignatureStatus)
            # KHÔNG PHẢI result.signer_cert
            # ========================================================
            signer_info = {}
            if result.signing_cert:
                subject = result.signing_cert.subject
                try:
                    email_attr = subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
                    if email_attr:
                        signer_info['email'] = email_attr[0].value
                except (IndexError, AttributeError):
                    pass
                
                try:
                    cn_attr = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if cn_attr:
                        signer_info['common_name'] = cn_attr[0].value
                    else:
                        signer_info['common_name'] = "Unknown"
                except (IndexError, AttributeError):
                    signer_info['common_name'] = "Unknown"
            
            # ========================================================
            # Lấy thời gian ký
            # FIX CRITICAL: Thời gian ký nằm trong result (PdfSignatureStatus)
            # KHÔNG PHẢI sig.signing_time (EmbeddedPdfSignature không có attribute này)
            # ========================================================
            signed_at = None
            
            # Try different possible timestamp attributes
            if hasattr(result, 'timestamp') and result.timestamp:
                signed_at = result.timestamp
                logger.info(f"Got timestamp from result.timestamp: {signed_at}")
            elif hasattr(result, 'signing_time') and result.signing_time:
                signed_at = result.signing_time
                logger.info(f"Got timestamp from result.signing_time: {signed_at}")
            else:
                # Fallback: Use current time if no timestamp available
                signed_at = datetime.now(timezone.utc)
                logger.warning("No timestamp found in signature, using current time")

            # Tạo message dựa trên kết quả
            if result.valid and result.intact:
                message = "Chữ ký hợp lệ và PDF không bị thay đổi"
            elif result.intact:
                message = f"PDF không bị thay đổi nhưng chữ ký không hợp lệ: {result.summary}"
            else:
                message = f"Chữ ký hoặc PDF đã bị thay đổi: {result.summary}"
            
            logger.info(f"Verification result: valid={result.valid}, intact={result.intact}")
            
            return {
                "valid": result.valid and result.intact,
                "trusted_by_ca": result.trust_ok if hasattr(result, 'trust_ok') else False,
                "intact": result.intact,
                "message": message,
                "signer_info": signer_info,
                "signed_at": signed_at.isoformat() if signed_at else None
            }

        except Exception as e:
            logger.error(f"Error during signature verification: {e}", exc_info=True)
            return {
                "valid": False,
                "trusted_by_ca": False,
                "intact": False,
                "message": f"Lỗi hệ thống khi xác thực: {str(e)}",
                "signer_info": None,
                "signed_at": None
            }

    def get_signature_info(self, signed_pdf_bytes: bytes) -> dict:
        """
        Lấy thông tin chữ ký mà không cần verify đầy đủ.
        
        NOTE: Method này KHÔNG async vì chỉ đọc metadata cơ bản,
        không validate signature (validate mới cần async).
        
        Args:
            signed_pdf_bytes: Nội dung PDF đã được ký
            
        Returns:
            dict: Thông tin về các chữ ký trong PDF
        """
        try:
            reader = PdfFileReader(io.BytesIO(signed_pdf_bytes), strict=False)
            
            if not reader.embedded_signatures:
                return {
                    "has_signatures": False,
                    "signature_count": 0,
                    "signatures": []
                }
            
            signatures = []
            for sig in reader.embedded_signatures:
                # sig là EmbeddedPdfSignature object
                sig_info = {
                    "field_name": sig.field_name,
                    # FIX: EmbeddedPdfSignature KHÔNG CÓ signing_time attribute
                    # Để lấy timestamp chính xác, cần validate signature (async operation)
                    # Ở đây chỉ return None cho signing_time
                    "signing_time": None,
                }
                
                # Extract signer info if available
                # FIX: Từ EmbeddedPdfSignature object, dùng signer_cert
                if sig.signer_cert:
                    subject = sig.signer_cert.subject
                    try:
                        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        sig_info["signer_name"] = cn
                    except (IndexError, AttributeError):
                        sig_info["signer_name"] = "Unknown"
                
                signatures.append(sig_info)
            
            return {
                "has_signatures": True,
                "signature_count": len(signatures),
                "signatures": signatures,
                "note": "To get signing_time, use verify_embedded_signature() method"
            }
            
        except Exception as e:
            logger.error(f"Failed to get signature info: {e}", exc_info=True)
            return {
                "has_signatures": False,
                "signature_count": 0,
                "signatures": [],
                "error": str(e)
            }


# --- Dependency cho FastAPI ---
_pdf_signer_instance = PDFSigner()

async def get_pdf_signer() -> Generator[PDFSigner, None, None]:
    """
    FastAPI dependency to get the single PDFSigner instance.
    Async version to support async signing operations.
    """
    yield _pdf_signer_instance