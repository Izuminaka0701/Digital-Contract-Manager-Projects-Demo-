"""
Users API (app/api/users.py)
"""
from fastapi import APIRouter, Depends, HTTPException, status
from app.models.schemas import UserResponse
from app.api.auth import get_current_user
from app.core.supabase_client import get_supabase

# FIX: Đổi tên 'router_users' thành 'router' cho nhất quán
router = APIRouter()


# FIX: Đổi '@router_users' thành '@router'
@router.get("/me", response_model=UserResponse)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """
    Get current user profile
    """
    return UserResponse(**current_user)


# FIX: Đổi '@router_users' thành '@router'
@router.get("/{user_id}", response_model=UserResponse)
async def get_user_profile(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get user profile by ID (only for admins or self)
    """
    # Only allow users to see their own profile
    if user_id != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this profile"
        )
    
    supabase = get_supabase()
    user = supabase.get_user(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(**user)
