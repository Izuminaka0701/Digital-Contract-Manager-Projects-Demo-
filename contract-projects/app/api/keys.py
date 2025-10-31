"""
Signing Keys API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
import uuid
from datetime import datetime

from app.models.schemas import KeyCreate, KeyResponse, KeyListResponse, KeyStatus, AuditAction
from app.api.auth import get_current_user, get_client_ip
from app.core.crypto import CryptoManager
from app.core.supabase_client import get_supabase

router = APIRouter()


@router.post("/generate", response_model=KeyResponse, status_code=status.HTTP_201_CREATED)
async def generate_key(
    key_data: KeyCreate,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Generate a new signing key pair
    """
    supabase = get_supabase()
    
    try:
        # Generate RSA key pair
        private_key_pem, public_key_pem = CryptoManager.generate_key_pair()
        
        # Encrypt private key with user password
        encrypted_data, salt, nonce = CryptoManager.encrypt_private_key(
            private_key_pem,
            key_data.password
        )
        
        # Calculate fingerprint
        fingerprint = CryptoManager.get_key_fingerprint(public_key_pem)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate key: {str(e)}"
        )
    
    # Create key record
    key_id = str(uuid.uuid4())
    key_record = {
        "id": key_id,
        "user_id": current_user["id"],
        "name": key_data.name,
        "public_key": public_key_pem.decode(),
        "encrypted_private_key": encrypted_data.hex(),
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "fingerprint": fingerprint,
        "status": KeyStatus.ACTIVE,
        "created_at": datetime.utcnow().isoformat()
    }
    
    created_key = supabase.create_key(key_record)
    
    if not created_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create key"
        )
    
    # Create audit log
    audit_data = {
        "user_id": current_user["id"],
        "action": AuditAction.KEY_GENERATE,
        "resource_type": "signing_key",
        "resource_id": key_id,
        "ip_address": get_client_ip(request),
        "user_agent": request.headers.get("User-Agent"),
        "details": {"name": key_data.name, "fingerprint": fingerprint},
        "created_at": datetime.utcnow().isoformat()
    }
    supabase.create_audit_log(audit_data)
    
    # Return response without sensitive data
    return KeyResponse(
        id=created_key["id"],
        user_id=created_key["user_id"],
        name=created_key["name"],
        public_key=created_key["public_key"],
        fingerprint=created_key["fingerprint"],
        status=created_key["status"],
        created_at=created_key["created_at"]
    )


@router.get("/", response_model=KeyListResponse)
async def list_keys(current_user: dict = Depends(get_current_user)):
    """
    List all signing keys for current user
    """
    supabase = get_supabase()
    keys = supabase.get_user_keys(current_user["id"])
    
    return KeyListResponse(
        keys=[
            KeyResponse(
                id=k["id"],
                user_id=k["user_id"],
                name=k["name"],
                public_key=k["public_key"],
                fingerprint=k["fingerprint"],
                status=k["status"],
                created_at=k["created_at"]
            )
            for k in keys
        ]
    )


@router.get("/{key_id}", response_model=KeyResponse)
async def get_key(
    key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get signing key by ID
    """
    supabase = get_supabase()
    key = supabase.get_key(key_id)
    
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found"
        )
    
    # Check ownership
    if key["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this key"
        )
    
    return KeyResponse(
        id=key["id"],
        user_id=key["user_id"],
        name=key["name"],
        public_key=key["public_key"],
        fingerprint=key["fingerprint"],
        status=key["status"],
        created_at=key["created_at"]
    )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_key(
    key_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete (revoke) a signing key
    """
    supabase = get_supabase()
    
    # Get key
    key = supabase.get_key(key_id)
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found"
        )
    
    # Check ownership
    if key["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this key"
        )
    
    # Delete key
    success = supabase.delete_key(key_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete key"
        )
    
    # Create audit log
    audit_data = {
        "user_id": current_user["id"],
        "action": AuditAction.KEY_DELETE,
        "resource_type": "signing_key",
        "resource_id": key_id,
        "ip_address": get_client_ip(request),
        "user_agent": request.headers.get("User-Agent"),
        "details": {"name": key["name"], "fingerprint": key["fingerprint"]},
        "created_at": datetime.utcnow().isoformat()
    }
    supabase.create_audit_log(audit_data)
    
    return None