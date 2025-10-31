"""
API endpoints package
"""
from fastapi import APIRouter

# Import routers
from app.api import auth, contracts, keys, users, audit

# Create main API router
api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# FIX: Đổi 'users.router_users' thành 'users.router' cho khớp với file users.py
api_router.include_router(users.router, prefix="/users", tags=["Users"])

api_router.include_router(contracts.router, prefix="/contracts", tags=["Contracts"])
api_router.include_router(keys.router, prefix="/keys", tags=["Signing Keys"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Logs"])

__all__ = ["api_router"]
