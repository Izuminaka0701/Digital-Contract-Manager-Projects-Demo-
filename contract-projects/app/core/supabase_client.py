"""
Supabase client and utilities
"""
# FIX: ĐÃ ĐỔI TÊN FILE, giờ import từ package 'supabase' GỐC
# KHÔNG được import 'app.core.supabase_client' (đó là tự gọi chính nó)
from supabase import create_client, Client

from typing import Optional, Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class SupabaseClient:
    """Wrapper for Supabase client with helper methods"""
    
    def __init__(self, url: str, key: str):
        """
        Initialize Supabase client
        
        Args:
            url: Supabase project URL
            key: Supabase API key
        """
        self.url = url
        self.key = key
        # 'Client' đã được import ở trên nên dùng thẳng.
        self._client: Optional[Client] = None
    
    @property
    def client(self) -> Client: # <-- Pylance sẽ hết báo lỗi ở đây
        """Get or create Supabase client"""
        if self._client is None:
            self._client = create_client(self.url, self.key)
        return self._client
    
    # User operations
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        try:
            response = self.client.table('users').select('*').eq('id', user_id).single().execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        try:
            response = self.client.table('users').select('*').eq('email', email).single().execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None
    
    def create_user(self, user_data: Dict) -> Optional[Dict]:
        """Create new user"""
        try:
            response = self.client.table('users').insert(user_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def update_user(self, user_id: str, updates: Dict) -> Optional[Dict]:
        """Update user"""
        try:
            response = self.client.table('users').update(updates).eq('id', user_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return None
    
    # Contract operations
    def get_contract(self, contract_id: str) -> Optional[Dict]:
        """Get contract by ID"""
        try:
            response = self.client.table('contracts').select('*').eq('id', contract_id).single().execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting contract {contract_id}: {e}")
            return None
    
    def list_contracts(self, user_id: str, limit: int, offset: int) -> Optional[tuple[list, int]]:
        try:
        # Thêm 'count="exact"' để yêu cầu Supabase đếm tổng số
            response = self.client.table("contracts") \
            .select("*", count="exact") \
            .eq("user_id", user_id) \
            .order("created_at", desc=True) \
            .limit(limit) \
            .offset(offset) \
            .execute()

        # Trả về cả data VÀ count
            return response.data, response.count 

        except Exception as e:
            logger.error(f"Error listing contracts for user {user_id}: {e}")
            return None, 0
    
    def create_contract(self, contract_data: Dict) -> Optional[Dict]:
        """Create new contract"""
        try:
            response = self.client.table('contracts').insert(contract_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating contract: {e}")
            return None
    
    def update_contract(self, contract_id: str, updates: Dict) -> Optional[Dict]:
        """Update contract"""
        try:
            response = self.client.table('contracts').update(updates).eq('id', contract_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error updating contract {contract_id}: {e}")
            return None
    
    # Key operations
    def get_user_keys(self, user_id: str) -> List[Dict]:
        """Get all keys for user"""
        try:
            response = (
                self.client.table('signing_keys')
                .select('*')
                .eq('user_id', user_id)
                .order('created_at', desc=True)
                .execute()
            )
            return response.data
        except Exception as e:
            logger.error(f"Error getting keys for user {user_id}: {e}")
            return []
    
    def create_key(self, key_data: Dict) -> Optional[Dict]:
        """Create new signing key"""
        try:
            response = self.client.table('signing_keys').insert(key_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating key: {e}")
            return None
    
    def get_key(self, key_id: str) -> Optional[Dict]:
        """Get signing key by ID"""
        try:
            response = self.client.table('signing_keys').select('*').eq('id', key_id).single().execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting key {key_id}: {e}")
            return None
    
    def delete_key(self, key_id: str) -> bool:
        """Delete signing key"""
        try:
            self.client.table('signing_keys').delete().eq('id', key_id).execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting key {key_id}: {e}")
            return False
    
    # Audit log operations
    def create_audit_log(self, log_data: Dict) -> Optional[Dict]:
        """Create audit log entry"""
        try:
            response = self.client.table('audit_logs').insert(log_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating audit log: {e}")
            return None
    
    def get_audit_logs(self, user_id: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get audit logs, optionally filtered by user"""
        try:
            query = self.client.table('audit_logs').select('*').order('created_at', desc=True).limit(limit)
            
            if user_id:
                query = query.eq('user_id', user_id)
            
            response = query.execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting audit logs: {e}")
            return []
    
    # Storage operations
    def upload_file(self, bucket: str, path: str, content: bytes, token: Optional[str] = None, content_type: Optional[str] = None) -> Optional[str]:
        """Upload file to Supabase Storage"""
        try:
            # response = self.client.storage.from_(bucket).upload(path, file_data)
            # Tạm thời comment lại dòng trên nếu 'upload' trả về response không như mong đợi
            # Giả sử upload thành công và trả về path
            headers: Dict[str, str] = {
                "Content-Type": content_type or "application/octet-stream"
            }
            if token: headers["Authorization"] = f"Bearer {token}"
            file_options = {"headers": headers}
            self.client.storage.from_(bucket).upload(path, content, file_options)
            return f"{bucket}/{path}" # Trả về path tạm thời, bạn cần check lại docs
        except Exception as e:
            logger.error(f"Error uploading file to {bucket}/{path}: {e}")
            return None
    
    def download_file(self, bucket: str, path: str) -> Optional[bytes]:
        """Download file from Supabase Storage"""
        try:
            response = self.client.storage.from_(bucket).download(path)
            return response
        except Exception as e:
            logger.error(f"Error downloading file from {bucket}/{path}: {e}")
            return None
    
    def delete_file(self, bucket: str, path: str) -> bool:
        """Delete file from Supabase Storage"""
        try:
            self.client.storage.from_(bucket).remove([path])
            return True
        except Exception as e:
            logger.error(f"Error deleting file from {bucket}/{path}: {e}")
            return False
    
    def get_public_url(self, bucket: str, path: str) -> str:
        """Get public URL for file"""
        return self.client.storage.from_(bucket).get_public_url(path)


# Global instance (will be initialized in config)
supabase_client: Optional[SupabaseClient] = None


def get_supabase() -> SupabaseClient:
    """Get Supabase client instance"""
    if supabase_client is None:
        raise RuntimeError("Supabase client not initialized")
    return supabase_client

