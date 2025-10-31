"""
Authentication API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import uuid
from datetime import datetime

from app.models.schemas import (
    UserCreate, UserLogin, UserResponse, TokenResponse, AuditLogCreate, AuditAction
)
from app.core.security import SecurityManager, get_password_hash, verify_password
from app.core.supabase_client import get_supabase
from app.config import settings

router = APIRouter()
security = HTTPBearer()
sec_manager = SecurityManager(settings.SECRET_KEY)


def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host if request.client else "unknown"


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Dependency to get current authenticated user"""
    token = credentials.credentials
    
    try:
        payload = sec_manager.verify_token(token, "access")
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        supabase = get_supabase()
        user = supabase.get_user(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, request: Request):
    """
    Register a new user
    """
    supabase = get_supabase()
    
    # Check if user already exists
    existing_user = supabase.get_user_by_email(user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password
    hashed_password = get_password_hash(user_data.password)
    
    # Create user
    user_dict = {
        "id": str(uuid.uuid4()),
        "email": user_data.email,
        "full_name": user_data.full_name,
        "password_hash": hashed_password,
        "created_at": datetime.utcnow().isoformat()
    }
    
    created_user = supabase.create_user(user_dict)
    
    if not created_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )
    
    # Create audit log
    audit_data = {
        "user_id": created_user["id"],
        "action": AuditAction.USER_REGISTER,
        "ip_address": get_client_ip(request),
        "user_agent": request.headers.get("User-Agent"),
        "created_at": datetime.utcnow().isoformat()
    }
    supabase.create_audit_log(audit_data)
    
    return UserResponse(**created_user)


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request):
    """
    Login and get access token
    """
    supabase = get_supabase()
    
    # Get user by email
    user = supabase.get_user_by_email(credentials.email)
    
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Create tokens
    token_data = {"sub": user["id"], "email": user["email"]}
    access_token = sec_manager.create_access_token(token_data)
    refresh_token = sec_manager.create_refresh_token(token_data)
    
    # Create audit log
    audit_data = {
        "user_id": user["id"],
        "action": AuditAction.USER_LOGIN,
        "ip_address": get_client_ip(request),
        "user_agent": request.headers.get("User-Agent"),
        "created_at": datetime.utcnow().isoformat()
    }
    supabase.create_audit_log(audit_data)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Refresh access token using refresh token
    """
    refresh_token = credentials.credentials
    
    try:
        payload = sec_manager.verify_token(refresh_token, "refresh")
        user_id = payload.get("sub")
        email = payload.get("email")
        
        # Create new tokens
        token_data = {"sub": user_id, "email": email}
        new_access_token = sec_manager.create_access_token(token_data)
        new_refresh_token = sec_manager.create_refresh_token(token_data)
        
        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token
        )
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get current user information
    """
    return UserResponse(**current_user)


@router.post("/logout")
async def logout(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Logout (create audit log)
    """
    supabase = get_supabase()
    
    # Create audit log
    audit_data = {
        "user_id": current_user["id"],
        "action": AuditAction.USER_LOGOUT,
        "ip_address": get_client_ip(request),
        "user_agent": request.headers.get("User-Agent"),
        "created_at": datetime.utcnow().isoformat()
    }
    supabase.create_audit_log(audit_data)
    
    return {"message": "Logged out successfully"}