-- ==================================================
-- PART 1: "NUKE" (XÓA SẠCH) SCHEMA "CÙI" (BUSTED) CŨ
-- Chạy mấy lệnh này trước để "dọn" (clean) "kho" (DB)
-- ==================================================

-- Tắt RLS (Bảo vệ) để "dọn" (clean) (FIX: Thêm IF EXISTS cho "an toàn")
ALTER TABLE IF EXISTS users DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS contracts DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS signing_keys DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS audit_logs DISABLE ROW LEVEL SECURITY;

-- "Nuke" (Xóa) hết "chuồng" (tables) cũ
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS contracts CASCADE;
DROP TABLE IF EXISTS signing_keys CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- "Nuke" (Xóa) "view" (thống kê) cũ
DROP VIEW IF EXISTS user_stats CASCADE;

-- "Nuke" (Xóa) "function" (hàm) cũ
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;


-- ==================================================
-- PART 2: "BUILD" (XÂY) SCHEMA "XỊN" (AWESOME) MỚI
-- Chạy cái SQL "xịn" (awesome) của bạn để "xây" (build) "kho" (DB) mới
-- ==================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);

-- ==================================================
-- ===== SỬA LỖI DATABASE Ở BẢNG NÀY =====
-- ==================================================
-- Contracts table
CREATE TABLE contracts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    
    file_path TEXT NOT NULL,         -- Path đến file GỐC
    file_hash VARCHAR(64) NOT NULL,  -- Hash của file GỐC
    
    -- signature TEXT, -- BỎ CỘT NÀY (Vì logic PKCS#7 lưu chữ ký trong file .signed.pdf)
    
    -- THÊM 3 CỘT MỚI ĐỂ KHỚP VỚI PYTHON
    signed_file_path TEXT,           -- Path đến file ĐÃ KÝ (.signed.pdf)
    reject_reason TEXT,              -- Lý do từ chối
    verification_details JSONB,      -- Kết quả verify (lưu dạng JSON)
    
    signing_key_id UUID,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'signed', 'verified', 'rejected')),
    signed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- ==================================================
-- ===== KẾT THÚC SỬA LỖI =====
-- ==================================================

-- Create indexes
CREATE INDEX idx_contracts_user_id ON contracts(user_id);
CREATE INDEX idx_contracts_status ON contracts(status);
CREATE INDEX idx_contracts_created_at ON contracts(created_at DESC);

-- Signing keys table
CREATE TABLE signing_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    salt VARCHAR(32) NOT NULL,
    nonce VARCHAR(24) NOT NULL,
    fingerprint VARCHAR(16) NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_signing_keys_user_id ON signing_keys(user_id);
CREATE INDEX idx_signing_keys_status ON signing_keys(status);

-- Add foreign key for signing_key_id in contracts
ALTER TABLE contracts 
ADD CONSTRAINT fk_contracts_signing_key 
FOREIGN KEY (signing_key_id) REFERENCES signing_keys(id) ON DELETE SET NULL;

-- Audit logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_contracts_updated_at BEFORE UPDATE ON contracts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_signing_keys_updated_at BEFORE UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) Policies

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE contracts ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Users policies
CREATE POLICY "Users can view own data" ON users
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own data" ON users
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Allow anyone to create an account (INSERT)" ON users
    FOR INSERT WITH CHECK (true);

-- Contracts policies
CREATE POLICY "Users can view own contracts" ON contracts
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own contracts" ON contracts
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own contracts" ON contracts
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own contracts" ON contracts
    FOR DELETE USING (auth.uid() = user_id);

-- Signing keys policies
CREATE POLICY "Users can view own keys" ON signing_keys
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own keys" ON signing_keys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own keys" ON signing_keys
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own keys" ON signing_keys
    FOR DELETE USING (auth.uid() = user_id);

-- Audit logs policies
CREATE POLICY "Users can view own audit logs" ON audit_logs
    FOR SELECT USING (auth.uid() = user_id);

-- Create storage bucket for contracts
INSERT INTO storage.buckets (id, name, public)
VALUES ('contracts', 'contracts', false)
ON CONFLICT (id) DO NOTHING;

-- Storage policies
DROP POLICY IF EXISTS "Users can upload own contracts" ON storage.objects;
CREATE POLICY "Users can upload own contracts" ON storage.objects
    FOR INSERT WITH CHECK (
        bucket_id = 'contracts' AND 
        auth.uid()::text = (storage.foldername(name))[1]
    );

DROP POLICY IF EXISTS "Users can view own contracts" ON storage.objects;
CREATE POLICY "Users can view own contracts" ON storage.objects
    FOR SELECT USING (
        bucket_id = 'contracts' AND 
        auth.uid()::text = (storage.foldername(name))[1]
    );

DROP POLICY IF EXISTS "Users can delete own contracts" ON storage.objects;
CREATE POLICY "Users can delete own contracts" ON storage.objects
    FOR DELETE USING (
        bucket_id = 'contracts' AND 
        auth.uid()::text = (storage.foldername(name))[1]
    );

-- Create views for statistics
CREATE OR REPLACE VIEW user_stats AS
SELECT 
    u.id AS user_id,
    u.email,
    u.full_name,
    COUNT(DISTINCT c.id) AS total_contracts,
    COUNT(DISTINCT CASE WHEN c.status = 'signed' THEN c.id END) AS signed_contracts,
    COUNT(DISTINCT CASE WHEN c.status = 'pending' THEN c.id END) AS pending_contracts,
    COUNT(DISTINCT k.id) AS total_keys,
    u.created_at
FROM users u
LEFT JOIN contracts c ON u.id = c.user_id
LEFT JOIN signing_keys k ON u.id = k.user_id AND k.status = 'active'
GROUP BY u.id, u.email, u.full_name, u.created_at;

-- Grant permissions on view
GRANT SELECT ON user_stats TO authenticated;

-- Comments for documentation
COMMENT ON TABLE users IS 'Stores user account information';
COMMENT ON TABLE contracts IS 'Stores contract documents and signatures';
COMMENT ON TABLE signing_keys IS 'Stores user cryptographic key pairs (private keys encrypted)';
COMMENT ON TABLE audit_logs IS 'Stores audit trail of all user actions';

ALTER TABLE public.signing_keys
ADD COLUMN certificate_pem TEXT;
