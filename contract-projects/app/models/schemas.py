"""
Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from enum import Enum


# Enums
class ContractStatus(str, Enum):
    PENDING = "pending"
    SIGNED = "signed"
    VERIFIED = "verified"
    REJECTED = "rejected"


class KeyStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class AuditAction(str, Enum):
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_REGISTER = "user_register"
    CONTRACT_UPLOAD = "contract_upload"
    CONTRACT_SIGN = "contract_sign"
    CONTRACT_VERIFY = "contract_verify"
    KEY_GENERATE = "key_generate"
    KEY_DELETE = "key_delete"


# User schemas
class UserBase(BaseModel):
    email: EmailStr
    full_name: str


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @validator('password')
    def validate_password(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(UserBase):
    id: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# Contract schemas
class ContractBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class ContractCreate(ContractBase):
    pass


class ContractSign(BaseModel):
    key_id: str
    key_password: Optional[str] = None


class ContractResponse(ContractBase):
    id: str
    user_id: str
    file_path: str
    file_hash: str
    signature: Optional[str] = None
    status: ContractStatus
    signed_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class ContractListResponse(BaseModel):
    contracts: List[ContractResponse]
    total: int
    page: int
    page_size: int


class ContractVerifyRequest(BaseModel):
    contract_id: str


class ContractVerifyResponse(BaseModel):
    valid: bool
    contract_id: str
    file_hash: str
    signature: Optional[str] = None
    signer_email: Optional[str] = None
    signed_at: Optional[datetime] = None
    message: str

class ContractReject(BaseModel):
    reason: Optional[str] = Field(None, max_length=500) # Thêm max_length cho an toàn DB

# Signing key schemas
class KeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8)


class KeyResponse(BaseModel):
    id: str
    user_id: str
    name: str
    public_key: str
    fingerprint: str
    status: KeyStatus
    created_at: datetime
    
    class Config:
        from_attributes = True


class KeyListResponse(BaseModel):
    keys: List[KeyResponse]


# Audit log schemas
class AuditLogCreate(BaseModel):
    user_id: Optional[str] = None
    action: AuditAction
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[dict] = None


class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Optional[dict]
    created_at: datetime
    
    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    logs: List[AuditLogResponse]
    total: int


# Dashboard schemas
class DashboardStats(BaseModel):
    total_contracts: int
    signed_contracts: int
    pending_contracts: int
    total_keys: int
    recent_activity: List[AuditLogResponse]


# Error response
class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None