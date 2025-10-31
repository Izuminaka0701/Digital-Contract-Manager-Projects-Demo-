"""
Contracts API endpoints
(ĐÃ SỬA: Dùng SERVICE_KEY, bỏ qua RLS token)
(ĐÃ SỬA: Điền đầy đủ các lỗi HTTPException)
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Request
from typing import Optional, List
import uuid
from datetime import datetime, timezone
import os 
import re 
import unicodedata 
import logging

from app.models.schemas import (
    ContractResponse, ContractListResponse,
    ContractSign, ContractVerifyRequest, ContractVerifyResponse,
    ContractStatus, AuditAction, ErrorResponse, ContractReject, KeyStatus
)
from app.api.auth import get_current_user, get_client_ip 
from app.core.crypto import CryptoManager
from app.core.pdf_signer import get_pdf_signer, PDFSigner 
from app.core.supabase_client import get_supabase, SupabaseClient
from app.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

def _get_utc_now() -> datetime:
    return datetime.now(timezone.utc)

def sanitize_filename(filename: str) -> str:
    root, ext = os.path.splitext(filename)
    root = unicodedata.normalize('NFKD', root).encode('ascii', 'ignore').decode('ascii')
    root = root.lower()
    root = re.sub(r'[^\w\s-]', '', root).strip()
    root = re.sub(r'[-\s]+', '-', root)
    if not root:
        root = str(uuid.uuid4().hex[:8])
    return f"{root}{ext}"


@router.post("/upload", 
    response_model=ContractResponse, 
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    }
)
async def upload_contract(
    request: Request,
    file: UploadFile = File(...),
    title: Optional[str] = None,
    description: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase)
):
    """
    Upload hợp đồng (Dùng SERVICE_KEY)
    """
    
    if not file.filename.endswith('.pdf'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are allowed"
        )
    
    logger.info(f"User {current_user['id']} uploading contract '{file.filename}'")
    
    content = await file.read()
    content_type = file.content_type 
    
    if len(content) > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum allowed size ({settings.MAX_UPLOAD_SIZE} bytes)"
        )
    
    contract_id = str(uuid.uuid4())
    file_hash = CryptoManager.hash_document(content)
    
    original_filename = file.filename
    safe_filename = sanitize_filename(original_filename)

    file_path = f"{current_user['id']}/{contract_id}/{safe_filename}"
    
    uploaded_path = supabase.upload_file(
        settings.STORAGE_BUCKET, 
        file_path, 
        content, 
        content_type=content_type
    )
    
    if not uploaded_path:
        logger.error(f"Failed to upload file to storage for contract {contract_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload file to storage"
        )
    
    logger.info(f"Original file uploaded to: {uploaded_path}")

    contract_data = {
        "id": contract_id,
        "user_id": current_user["id"],
        "title": title or original_filename,
        "description": description,
        "file_path": file_path,
        "file_hash": file_hash,
        "status": ContractStatus.PENDING.value,
        "created_at": _get_utc_now().isoformat(),
        "updated_at": _get_utc_now().isoformat(),
        "signed_file_path": None,
        "reject_reason": None,
        "signing_key_id": None,
        "signed_at": None,
        "verification_details": None
    }
    
    contract = supabase.create_contract(contract_data)
    
    if not contract:
        logger.error(f"Failed to create contract record in DB for {contract_id}")
        supabase.delete_file(settings.STORAGE_BUCKET, file_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create contract record in database"
        )
    
    _log_audit(
        supabase, current_user["id"], AuditAction.CONTRACT_UPLOAD, request, contract_id, 
        {"filename": original_filename, "file_hash": file_hash}
    )
    
    return ContractResponse(**contract)


@router.get("/", response_model=ContractListResponse)
async def list_contracts(
    page: int = 1,
    page_size: int = 20,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase)
):
    """
    List hợp đồng (Đã sửa lỗi unpack tuple)
    """
    logger.info(f"Listing contracts (v1 Single-Signer) for user {current_user['id']}")
    offset = (page - 1) * page_size
    
    contracts_raw, total_count = supabase.list_contracts(current_user["id"], limit=page_size, offset=offset)
    
    if contracts_raw is None:
        contracts_raw = []
    
    return ContractListResponse(
        contracts=[ContractResponse(**c) for c in contracts_raw],
        total=total_count or 0,
        page=page,
        page_size=page_size
    )


@router.get("/{contract_id}", 
    response_model=ContractResponse,
    responses={404: {"model": ErrorResponse}, 403: {"model": ErrorResponse}}
)
async def get_contract(
    contract_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase)
):
    """
    Lấy chi tiết hợp đồng
    """
    contract = _get_and_authorize_contract(supabase, current_user["id"], contract_id)
    return ContractResponse(**contract)


@router.post("/{contract_id}/sign", 
    response_model=ContractResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
async def sign_contract(
    contract_id: str,
    sign_data: ContractSign,
    request: Request,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase),
    pdf_signer: PDFSigner = Depends(get_pdf_signer)
):
    """
    Ký hợp đồng (Dùng SERVICE_KEY)
    """
    logger.info(f"User {current_user['id']} attempting to sign contract {contract_id} with key {sign_data.key_id}")
    
    contract = _get_and_authorize_contract(supabase, current_user["id"], contract_id)
    
    # SỬA LỖI: Điền lại HTTPException (đây là dòng 217 của bạn)
    if contract["status"] != ContractStatus.PENDING.value:
        logger.warning(f"Sign attempt on non-pending contract {contract_id} (Status: {contract['status']})")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Contract is not in 'pending' status. Current status: {contract['status']}"
        )
    
    key = _get_and_authorize_key(supabase, current_user["id"], sign_data.key_id)
    
    # SỬA LỖI: Điền lại HTTPException
    if not key.get("certificate_pem"):
        logger.error(f"Key {key['id']} 'khong co' (missing) 'certificate_pem'.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This signing key has no certificate. Please generate a new key."
        )

    # 3. "Tai" (Download) PDF "GOC" (ORIGINAL)
    pdf_bytes = supabase.download_file(
        settings.STORAGE_BUCKET, 
        contract["file_path"]
    ) 
    # SỬA LỖI: Điền lại HTTPException
    if not pdf_bytes:
        logger.error(f"Failed to download original PDF {contract['file_path']} for signing.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to retrieve contract file for signing."
        )

    # 4. "Giai ma" (Decrypt) "Key" (Khoa) "Bi mat" (Private)
    try:
        private_key_pem_bytes = CryptoManager.decrypt_private_key(
            bytes.fromhex(key["encrypted_private_key"]),
            bytes.fromhex(key["salt"]),
            bytes.fromhex(key["nonce"]),
            sign_data.key_password or ""
        )
    except Exception as e:
        logger.warning(f"Failed to decrypt key {key['id']} for signing: {e}")
        _log_audit(
            supabase, current_user["id"], AuditAction.CONTRACT_SIGN, 
            request, contract_id, {"key_id": key['id'], "error": "Invalid password"}
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid key password")

    # 5. "KY NHUNG" (EMBED SIGN) "PKCS#7"
    try:
        signed_pdf_bytes = pdf_signer.embed_signature(
            pdf_bytes=pdf_bytes,
            signer_private_key_pem=private_key_pem_bytes,
            signer_cert_pem=key["certificate_pem"], 
            signature_meta={
                "reason": "I agree to the terms of this contract",
                "location": f"Signed via {settings.APP_NAME}",
                "name": current_user["full_name"]
            }
        )
    except Exception as e:
        logger.error(f"pyhanko failed to embed signature for contract {contract_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Failed to embed signature in PDF: {e}"
        )

    # 6. "Up" (Upload) file ".signed.pdf" "moi" (new)
    original_safe_name = os.path.basename(contract["file_path"])
    base_name, ext = os.path.splitext(original_safe_name)
    signed_filename = f"{base_name}.signed{ext}"
    signed_file_path = f"{current_user['id']}/{contract_id}/{signed_filename}"
    
    uploaded_signed_path = supabase.upload_file(
        settings.STORAGE_BUCKET, 
        signed_file_path, 
        signed_pdf_bytes,
        content_type="application/pdf"
    )
    # SỬA LỖI: Điền lại HTTPException
    if not uploaded_signed_path:
        logger.error(f"Failed to upload SIGNED PDF {signed_file_path} to storage.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to save signed contract file."
        )
    
    logger.info(f"Signed PDF uploaded to: {uploaded_signed_path}")

    # 7. "Update" (Cap nhat) "Hop dong" (Contract) "trong" (in) "Kho" (DB)
    now = _get_utc_now()
    updates = {
        "status": ContractStatus.SIGNED.value,
        "signed_at": now.isoformat(),
        "signing_key_id": sign_data.key_id,
        "signed_file_path": signed_file_path, 
        "updated_at": now.isoformat()
    }
    
    updated_contract = supabase.update_contract(contract_id, updates)
    # SỬA LỖI: Điền lại HTTPException
    if not updated_contract:
        logger.error(f"Failed to update contract {contract_id} status in DB after signing.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to update contract status after signing."
        )

    _log_audit(
        supabase, current_user["id"], AuditAction.CONTRACT_SIGN, request, contract_id, 
        {"key_id": sign_data.key_id, "signed_file_path": signed_file_path}
    )
    
    return ContractResponse(**updated_contract)


@router.post("/{contract_id}/reject", 
    response_model=ContractResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse}
    }
)
async def reject_contract(
    contract_id: str,
    reject_data: ContractReject,
    request: Request,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase)
):
    """
    "TU CHOI" (REJECT) "KY" (SIGNING) "HOP DONG" (CONTRACT)
    """
    logger.info(f"User {current_user['id']} attempting to reject contract {contract_id}")
    contract = _get_and_authorize_contract(supabase, current_user["id"], contract_id)

    if contract["status"] != ContractStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Contract cannot be rejected (Status: {contract['status']})"
        )

    now = _get_utc_now()
    updates = {
        "status": ContractStatus.REJECTED.value,
        "reject_reason": reject_data.reason or "No reason provided",
        "updated_at": now.isoformat()
    }

    updated_contract = supabase.update_contract(contract_id, updates)
    if not updated_contract:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update contract status to rejected.")

    _log_audit(
        supabase, current_user["id"], AuditAction.CONTRACT_REJECT, request, contract_id, 
        {"reason": reject_data.reason}
    )

    return ContractResponse(**updated_contract)


@router.post("/verify", 
    response_model=ContractVerifyResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}}
)
async def verify_contract(
    verify_data: ContractVerifyRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase),
    pdf_signer: PDFSigner = Depends(get_pdf_signer)
):
    """
    "VERIFY" (XAC THUC) "CHU KY" (SIGNATURE) "NHUNG" (EMBEDDED) "PKCS#7"
    """
    logger.info(f"User {current_user['id']} attempting to verify contract {verify_data.contract_id}")
    
    contract = supabase.get_contract(verify_data.contract_id)
    if not contract:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contract not found")
        
    if contract["status"] != ContractStatus.SIGNED.value or not contract.get("signed_file_path"):
        logger.warning(f"Verification attempt on non-signed contract {verify_data.contract_id}")
        return ContractVerifyResponse(
            valid=False,
            trusted_by_ca=False,
            intact=False,
            message="Contract is not signed or the signed file path is missing.",
            contract_id=verify_data.contract_id,
            file_hash=contract["file_hash"]
        )
    
    # "Tai" (Download) file "DA KY" (SIGNED)
    signed_pdf_bytes = supabase.download_file(
        settings.STORAGE_BUCKET, 
        contract["signed_file_path"]
    )
    # SỬA LỖI: Điền lại HTTPException
    if not signed_pdf_bytes:
        logger.error(f"Failed to download SIGNED PDF {contract['signed_file_path']} for verification.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to retrieve signed contract file."
        )
        
    # "VERIFY" (XAC THUC)
    verification_results = pdf_signer.verify_embedded_signature(signed_pdf_bytes)

    # "Luu" (Save) "ket qua" (result) "verify" (xac thuc) "vao" (into) "kho" (DB)
    supabase.update_contract(verify_data.contract_id, {"verification_details": verification_results})

    _log_audit(
        supabase, current_user["id"], AuditAction.CONTRACT_VERIFY, request, verify_data.contract_id, 
        {"verification_valid": verification_results.get("valid", False)}
    )

    return ContractVerifyResponse(
        contract_id=verify_data.contract_id,
        file_hash=contract["file_hash"],
        **verification_results 
    )

# --- "Ham" (Helpers) "Rut Gon" (Shortcut) ---

def _get_and_authorize_contract(supabase: SupabaseClient, user_id: str, contract_id: str) -> dict:
    """"Lay" (Gets) "hop dong" (contract) "va" (and) "check" (kiem tra) "quyen" (permission) "so huu" (owner)."""
    contract = supabase.get_contract(contract_id)
    if not contract:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contract not found")
    if contract["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this contract")
    return contract

def _get_and_authorize_key(supabase: SupabaseClient, user_id: str, key_id: str) -> dict:
    """"Lay" (Gets) "key" (khoa) "va" (and) "check" (kiem tra) "quyen" (permission) "so huu" (owner)."""
    key = supabase.get_key(key_id)
    if not key:
        raise HTTPException(status_code=status.HTTP_440_NOT_FOUND, detail="Signing key not found") # Sửa lỗi typo 440 -> 404
    if key["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to use this key")
    if key["status"] != KeyStatus.ACTIVE.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Signing key is not active (Status: {key['status']})")
    return key

def _log_audit(supabase: SupabaseClient, user_id: str, action: AuditAction, request: Request, resource_id: str, details: dict):
    """"Ham" (Helper) "de" (to) "log" (ghi) audit "cho" (for) "gon" (clean)."""
    try:
        audit_data = {
            "user_id": user_id,
            "action": action.value,
            "resource_type": "contract",
            "resource_id": resource_id,
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("User-Agent"),
            "details": details,
            "created_at": _get_utc_now().isoformat()
        }
        supabase.create_audit_log(audit_data)
    except Exception as e:
        logger.error(f"Failed to create audit log for contract action {action} on {resource_id}: {e}", exc_info=True)