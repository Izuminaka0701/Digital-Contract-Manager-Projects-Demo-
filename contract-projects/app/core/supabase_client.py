# app/core/supabase_client.py

import httpx
import logging
import mimetypes
from typing import Optional, List, Dict, Any, Tuple
from supabase import create_client, Client
from app.config import settings

logger = logging.getLogger(__name__)

# Biến này sẽ được gán giá trị khi server khởi động (trong app/main.py)
supabase_client: Optional[Client] = None

class SupabaseClient:
    def __init__(self, url: str, key: str):
        # 'key' này BẮT BUỘC PHẢI LÀ SERVICE_KEY
        self.client: Client = create_client(url, key)
        self.storage_url = f"{url}/storage/v1"
        logger.info("SupabaseClient initialized (Sử dụng SERVICE_KEY)")

    # ========================================================
    # FIX LỖI MIME TYPE - DÙNG "content-type" THAY VÌ "contentType"
    # ========================================================
    def upload_file(self, bucket: str, path: str, content: bytes, 
                    content_type: Optional[str] = None,
                    filename: Optional[str] = None) -> Optional[str]:
        """
        Uploads a file bằng SERVICE_KEY.
        Tự động detect MIME type từ filename hoặc sử dụng content_type truyền vào.
        
        Args:
            bucket: Tên bucket trong Supabase Storage
            path: Đường dẫn file trong bucket
            content: Nội dung file dạng bytes
            content_type: MIME type (optional, sẽ auto-detect nếu không có)
            filename: Tên file để auto-detect MIME type
            
        Returns:
            str: Path của file đã upload, hoặc None nếu lỗi
        """
        try:
            # Auto-detect MIME type nếu không được truyền vào
            if not content_type:
                if filename:
                    # Detect từ filename
                    guessed_type = mimetypes.guess_type(filename)[0]
                    content_type = guessed_type or "application/octet-stream"
                    logger.info(f"Auto-detected MIME type: {content_type} for {filename}")
                else:
                    # Default fallback
                    content_type = "application/octet-stream"
            
            # FIX: Supabase Storage yêu cầu dùng "content-type" (lowercase với dấu gạch ngang)
            # KHÔNG PHẢI "contentType" (camelCase)
            file_options = {
                "content-type": content_type,  # <-- KEY FIX Ở ĐÂY
                "x-upsert": "true"  # Cho phép ghi đè nếu file đã tồn tại
            }

            logger.info(f"Uploading file to {path} with MIME type: {content_type}")

            response = self.client.storage \
                .from_(bucket) \
                .upload(
                    path, 
                    content,
                    file_options=file_options
                )
            
            logger.info(f"File uploaded successfully to {path}")
            return path

        except Exception as e:
            logger.error(f"Error uploading file to {path}: {e}", exc_info=True)
            return None

    # ========================================================
    # HÀM DOWNLOAD (Dùng SERVICE_KEY)
    # ========================================================
    def download_file(self, bucket: str, path: str) -> Optional[bytes]:
        """Downloads a file bằng SERVICE_KEY."""
        try:
            content = self.client.storage.from_(bucket).download(path)
            logger.info(f"File downloaded successfully from {path}")
            return content
        except Exception as e:
            logger.error(f"Error downloading file from {path}: {e}", exc_info=True)
            return None

    # ========================================================
    # HÀM DELETE (Dùng SERVICE_KEY)
    # ========================================================
    def delete_file(self, bucket: str, path: str) -> bool:
        """Deletes a file bằng SERVICE_KEY."""
        try:
            self.client.storage.from_(bucket).remove([path])
            logger.info(f"File deleted successfully: {path}")
            return True
        except Exception as e:
            logger.error(f"Error deleting file {path}: {e}", exc_info=True)
            return False

    # ========================================================
    # HÀM GET PUBLIC URL (Nếu bucket là public)
    # ========================================================
    def get_public_url(self, bucket: str, path: str) -> str:
        """
        Lấy public URL của file.
        Chỉ hoạt động nếu bucket được set là public.
        """
        try:
            url = self.client.storage.from_(bucket).get_public_url(path)
            return url
        except Exception as e:
            logger.error(f"Error getting public URL for {path}: {e}")
            return ""

    # ========================================================
    # HÀM CREATE SIGNED URL (Cho private bucket)
    # ========================================================
    def create_signed_url(self, bucket: str, path: str, expires_in: int = 3600) -> Optional[str]:
        """
        Tạo signed URL có thời hạn cho file trong private bucket.
        
        Args:
            bucket: Tên bucket
            path: Đường dẫn file
            expires_in: Thời gian hết hạn (giây), mặc định 1 giờ
            
        Returns:
            str: Signed URL hoặc None nếu lỗi
        """
        try:
            response = self.client.storage.from_(bucket).create_signed_url(path, expires_in)
            if response and 'signedURL' in response:
                return response['signedURL']
            return None
        except Exception as e:
            logger.error(f"Error creating signed URL for {path}: {e}")
            return None

    # --- CÁC HÀM DATABASE ---
    
    def create_user(self, user_data: Dict[str, Any]) -> Optional[dict]:
        """Tạo user mới trong database."""
        try:
            response = self.client.table("users").insert(user_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating user: {e}", exc_info=True)
            return None

    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Lấy thông tin user theo email."""
        try:
            response = self.client.table("users").select("*").eq("email", email).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting user by email: {e}", exc_info=True)
            return None
            
    def get_user(self, user_id: str) -> Optional[dict]:
        """Lấy thông tin user theo ID."""
        try:
            response = self.client.table("users").select("*").eq("id", user_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting user by id: {e}", exc_info=True)
            return None

    def create_contract(self, contract_data: Dict[str, Any]) -> Optional[dict]:
        """Tạo contract mới trong database."""
        try:
            response = self.client.table("contracts").insert(contract_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating contract: {e}", exc_info=True)
            return None

    def update_contract(self, contract_id: str, updates: Dict[str, Any]) -> Optional[dict]:
        """Cập nhật thông tin contract."""
        try:
            response = self.client.table("contracts").update(updates).eq("id", contract_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error updating contract {contract_id}: {e}", exc_info=True)
            return None

    def get_contract(self, contract_id: str) -> Optional[dict]:
        """Lấy thông tin contract theo ID."""
        try:
            response = self.client.table("contracts").select("*").eq("id", contract_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting contract {contract_id}: {e}", exc_info=True)
            return None

    def list_contracts(self, user_id: str, limit: int, offset: int) -> Tuple[Optional[List[dict]], Optional[int]]:
        """Lấy danh sách contracts của user với pagination."""
        try:
            response = self.client.table("contracts") \
                .select("*", count="exact") \
                .eq("user_id", user_id) \
                .order("created_at", desc=True) \
                .limit(limit) \
                .offset(offset) \
                .execute()
            return response.data, response.count
        except Exception as e:
            logger.error(f"Error listing contracts for user {user_id}: {e}", exc_info=True)
            return None, 0

    def get_key(self, key_id: str) -> Optional[dict]:
        """Lấy thông tin signing key theo ID."""
        try:
            response = self.client.table("signing_keys").select("*").eq("id", key_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting key {key_id}: {e}", exc_info=True)
            return None
            
    def get_user_keys(self, user_id: str) -> Optional[List[dict]]:
        """Lấy tất cả signing keys của user."""
        try:
            response = self.client.table("signing_keys") \
                .select("*") \
                .eq("user_id", user_id) \
                .order("created_at", desc=True) \
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting keys for user {user_id}: {e}", exc_info=True)
            return None
            
    def count_keys(self, user_id: str) -> Optional[int]:
        """Đếm số lượng signing keys của user."""
        try:
            response = self.client.table("signing_keys") \
                .select("*", count="exact") \
                .eq("user_id", user_id) \
                .execute()
            return response.count
        except Exception as e:
            logger.error(f"Error counting keys for user {user_id}: {e}", exc_info=True)
            return 0
            
    def list_audit_logs(self, user_id: str, limit: int, offset: int) -> Tuple[Optional[List[dict]], Optional[int]]:
        """Lấy audit logs của user với pagination."""
        try:
            response = self.client.table("audit_logs") \
                .select("*", count="exact") \
                .eq("user_id", user_id) \
                .order("created_at", desc=True) \
                .limit(limit) \
                .offset(offset) \
                .execute()
            return response.data, response.count
        except Exception as e:
            logger.error(f"Error listing audit logs for user {user_id}: {e}", exc_info=True)
            return None, 0

    def create_audit_log(self, log_data: Dict[str, Any]) -> None:
        """Tạo audit log entry."""
        try:
            self.client.table("audit_logs").insert(log_data).execute()
            logger.info(f"Audit log created: {log_data.get('action', 'unknown')}")
        except Exception as e:
            logger.error(f"Error creating audit log: {e}", exc_info=True)

# --- Dependency Injection ---

def get_supabase() -> SupabaseClient:
    """FastAPI dependency to get the initialized Supabase client."""
    if supabase_client is None:
        logger.critical("Supabase client not initialized!")
        raise RuntimeError("Supabase client not initialized")
    return supabase_client

def init_supabase_client():
    """Initializes the global Supabase client."""
    global supabase_client
    if supabase_client is None:
        supabase_client = SupabaseClient(
            settings.SUPABASE_URL,
            settings.SUPABASE_KEY  # PHẢI LÀ SERVICE_KEY
        )
        logger.info("Global Supabase client has been initialized.")

def close_supabase_client():
    """Closes the Supabase client (nếu thư viện hỗ trợ)."""
    global supabase_client
    supabase_client = None
    logger.info("Global Supabase client has been shut down.")