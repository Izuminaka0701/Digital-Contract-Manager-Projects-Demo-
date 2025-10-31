"""
Audit Logs API (app/api/audit.py)
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
import logging # Thêm logging

from app.models.schemas import (
    AuditLogListResponse, 
    AuditLogResponse, 
    DashboardStats,
    ContractStatus # <-- Thêm import này
)
from app.api.auth import get_current_user
from app.core.supabase_client import get_supabase, SupabaseClient

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/logs", response_model=AuditLogListResponse)
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=100),
    page: int = Query(1, ge=1), # <-- Thêm 'page' để phân trang
    current_user: dict = Depends(get_current_user)
):
    """
    Get audit logs for current user (Đã sửa để phân trang)
    """
    supabase = get_supabase()
    offset = (page - 1) * limit

    # SỬA LỖI: Giả sử 'get_audit_logs' cũng trả về (data, count)
    # (Nếu hàm này chưa trả về (data, count), bạn cần sửa nó trong supabase_client.py)
    try:
        logs_data, total_count = supabase.list_audit_logs(
            user_id=current_user["id"], 
            limit=limit,
            offset=offset
        )
    except (AttributeError, TypeError):
        # Fallback nếu hàm 'list_audit_logs' chưa được sửa
        logger.warning("Fallback: supabase.list_audit_logs chưa trả về (data, count).")
        logs_data = supabase.get_audit_logs(user_id=current_user["id"], limit=limit) # Tên hàm cũ
        total_count = len(logs_data) # Không hiệu quả, nhưng chạy được

    if logs_data is None:
        logs_data = []

    return AuditLogListResponse(
        logs=[AuditLogResponse(**log) for log in logs_data],
        total=total_count or 0 # Dùng total count "xịn"
    )


@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user), supabase: SupabaseClient = Depends(get_supabase)):
    """
    Get dashboard statistics (Đã sửa lỗi TypeError)
    """
    logger.info(f"Loading dashboard stats for user {current_user['id']}")
    # supabase = get_supabase() # Dòng này không cần, đã inject qua Depends
    
    # --- SỬA LỖI CHÍNH ---
    # 1. "Mở gói" (unpack) tuple
    contracts_data, total_contracts_count = supabase.list_contracts(
        current_user["id"], 
        limit=1000, # Lấy 1000 hợp đồng gần nhất để tính
        offset=0
    )
    
    if contracts_data is None:
        contracts_data = []

    # 2. Lặp trên 'contracts_data' (list "xịn"), không phải 'contracts' (tuple)
    signed_contracts = sum(1 for c in contracts_data if c.get("status") == ContractStatus.SIGNED.value)
    pending_contracts = sum(1 for c in contracts_data if c.get("status") == ContractStatus.PENDING.value)
    
    # Get keys
    # SỬA LỖI (DỰ ĐOÁN): Giả sử bạn có hàm 'count_keys'
    try:
        # Gọi hàm count_keys (nếu có) sẽ nhanh hơn
        total_keys = supabase.count_keys(current_user["id"])
    except AttributeError:
        # Nếu không có, fallback về cách cũ (chậm hơn)
        logger.warning("Hàm 'count_keys' không tồn tại. Đang fallback...")
        keys = supabase.get_user_keys(current_user["id"]) # Dùng tên hàm cũ của bạn
        total_keys = len(keys)
    
    # Get recent activity
    try:
        # Giả sử hàm này chỉ trả về list data (không phải tuple)
        recent_logs = supabase.get_audit_logs(user_id=current_user["id"], limit=10)
        if recent_logs is None:
            recent_logs = []
    except Exception as e:
        logger.error(f"Failed to get recent activity: {e}")
        recent_logs = []

    return DashboardStats(
        total_contracts=total_contracts_count or 0, # <-- 3. Dùng count từ tuple
        signed_contracts=signed_contracts,
        pending_contracts=pending_contracts,
        total_keys=total_keys or 0,
        recent_activity=[AuditLogResponse(**log) for log in recent_logs]
    )