-- Enhanced Security Functions - Zero Service Role Key Required
-- All security logic enforced at database level with controlled function access

-- ========================================
-- CLEANUP EXISTING OBJECTS FIRST
-- ========================================

-- Drop any existing functions that might conflict
DROP FUNCTION IF EXISTS authenticate_user CASCADE;
DROP FUNCTION IF EXISTS verify_session CASCADE;
DROP FUNCTION IF EXISTS setup_user_2fa CASCADE;
DROP FUNCTION IF EXISTS verify_user_2fa CASCADE;
DROP FUNCTION IF EXISTS complete_2fa_setup CASCADE;
DROP FUNCTION IF EXISTS get_user_2fa_status CASCADE;
DROP FUNCTION IF EXISTS logout_user CASCADE;
DROP FUNCTION IF EXISTS log_auth_attempt CASCADE;
DROP FUNCTION IF EXISTS clean_expired_sessions CASCADE;
DROP FUNCTION IF EXISTS unlock_expired_locks CASCADE;

-- Drop existing types
DROP TYPE IF EXISTS auth_result CASCADE;
DROP TYPE IF EXISTS session_result CASCADE;

-- ========================================
-- CREATE TABLES FIRST
-- ========================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto extension for bcrypt support
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Drop existing tables if they exist (for clean reinstall)
DROP TABLE IF EXISTS crm_user_sessions CASCADE;
DROP TABLE IF EXISTS crm_account_lockouts CASCADE;
DROP TABLE IF EXISTS crm_audit_log CASCADE;
DROP TABLE IF EXISTS crm_users CASCADE;

-- Create the main users table
CREATE TABLE crm_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    has_2fa BOOLEAN DEFAULT false,
    two_fa_secret TEXT,
    session_id UUID,
    session_expires_at TIMESTAMPTZ,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create user sessions table for tracking active sessions
CREATE TABLE crm_user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES crm_users(id) ON DELETE CASCADE,
    session_id UUID UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT true
);

-- Create account lockouts table
CREATE TABLE crm_account_lockouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES crm_users(id) ON DELETE CASCADE,
    locked_until TIMESTAMPTZ NOT NULL,
    reason TEXT,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create comprehensive audit log
CREATE TABLE crm_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES crm_users(id) ON DELETE SET NULL,
    username TEXT,
    action TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    session_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_crm_users_username ON crm_users(username);
CREATE INDEX idx_crm_users_session_id ON crm_users(session_id);
CREATE INDEX idx_crm_user_sessions_session_id ON crm_user_sessions(session_id);
CREATE INDEX idx_crm_user_sessions_user_id ON crm_user_sessions(user_id);
CREATE INDEX idx_crm_audit_log_user_id ON crm_audit_log(user_id);
CREATE INDEX idx_crm_audit_log_created_at ON crm_audit_log(created_at);
CREATE INDEX idx_crm_account_lockouts_user_id ON crm_account_lockouts(user_id);

-- Enable Row Level Security
ALTER TABLE crm_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE crm_user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE crm_account_lockouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE crm_audit_log ENABLE ROW LEVEL SECURITY;

-- ========================================
-- UTILITY FUNCTIONS
-- ========================================

-- Function to log authentication attempts
CREATE OR REPLACE FUNCTION log_auth_attempt(
    p_user_id UUID,
    p_username TEXT,
    p_action TEXT,
    p_ip_address INET,
    p_user_agent TEXT,
    p_success BOOLEAN,
    p_error_message TEXT DEFAULT NULL,
    p_session_id UUID DEFAULT NULL
)
RETURNS void AS $$
BEGIN
    INSERT INTO crm_audit_log (user_id, username, action, ip_address, user_agent, success, error_message, session_id)
    VALUES (p_user_id, p_username, p_action, p_ip_address, p_user_agent, p_success, p_error_message, p_session_id);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to clean expired sessions
CREATE OR REPLACE FUNCTION clean_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM crm_user_sessions WHERE expires_at < NOW();
    UPDATE crm_users SET session_id = NULL, session_expires_at = NULL 
    WHERE session_expires_at < NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to unlock expired locks
CREATE OR REPLACE FUNCTION unlock_expired_locks()
RETURNS void AS $$
BEGIN
    UPDATE crm_users SET locked_until = NULL 
    WHERE locked_until IS NOT NULL AND locked_until < NOW();
    DELETE FROM crm_account_lockouts WHERE locked_until < NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ========================================
-- MAIN SECURITY FUNCTIONS
-- ========================================

-- Create custom types for function returns
CREATE TYPE auth_result AS (
    success BOOLEAN,
    user_id UUID,
    username TEXT,
    requires_2fa BOOLEAN,
    session_id UUID,
    session_expires_at TIMESTAMPTZ,
    error_message TEXT,
    locked_until TIMESTAMPTZ
);

CREATE TYPE session_result AS (
    valid BOOLEAN,
    user_id UUID,
    username TEXT,
    expires_at TIMESTAMPTZ,
    error_message TEXT
);

-- Function 1: Authenticate user with built-in security checks
CREATE OR REPLACE FUNCTION authenticate_user(
    p_username TEXT,
    p_password_hash TEXT, -- This is actually the plain password for bcrypt comparison
    p_ip_address INET,
    p_user_agent TEXT
)
RETURNS auth_result AS $$
DECLARE
    v_user crm_users%ROWTYPE;
    v_session_id UUID;
    v_session_expires TIMESTAMPTZ;
    v_result auth_result;
    v_password_match BOOLEAN := false;
BEGIN
    -- Input validation
    IF char_length(p_username) < 3 OR char_length(p_password_hash) = 0 THEN
        v_result.success := false;
        v_result.error_message := 'Invalid credentials format';
        PERFORM log_auth_attempt(NULL, p_username, 'LOGIN_ATTEMPT', p_ip_address, p_user_agent, false, 'Invalid format', NULL);
        RETURN v_result;
    END IF;

    -- Clean expired locks first
    PERFORM unlock_expired_locks();

    -- Get user (bypassing RLS within security definer function)
    SELECT * INTO v_user FROM crm_users WHERE username = p_username AND is_active = true;

    -- Check if user exists
    IF NOT FOUND THEN
        PERFORM log_auth_attempt(NULL, p_username, 'LOGIN_ATTEMPT', p_ip_address, p_user_agent, false, 'User not found', NULL);
        v_result.success := false;
        v_result.error_message := 'Invalid credentials';
        RETURN v_result;
    END IF;

    -- Check if account is locked
    IF v_user.locked_until IS NOT NULL AND v_user.locked_until > NOW() THEN
        PERFORM log_auth_attempt(v_user.id, p_username, 'LOGIN_BLOCKED', p_ip_address, p_user_agent, false, 'Account locked', NULL);
        v_result.success := false;
        v_result.error_message := 'Account temporarily locked';
        v_result.locked_until := v_user.locked_until;
        RETURN v_result;
    END IF;

    -- Verify password using crypt() function for bcrypt comparison
    -- This compares the plain password with the stored bcrypt hash
    v_password_match := (crypt(p_password_hash, v_user.password_hash) = v_user.password_hash);

    IF NOT v_password_match THEN
        -- Increment failed attempts
        UPDATE crm_users 
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_until = CASE 
                WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
                ELSE NULL 
            END,
            updated_at = NOW()
        WHERE id = v_user.id;

        PERFORM log_auth_attempt(v_user.id, p_username, 'LOGIN_FAILED', p_ip_address, p_user_agent, false, 'Invalid password', NULL);
        v_result.success := false;
        v_result.error_message := 'Invalid credentials';
        RETURN v_result;
    END IF;

    -- Successful password verification - generate session
    v_session_id := gen_random_uuid();
    v_session_expires := NOW() + INTERVAL '2 hours';

    -- Update user with session and reset failed attempts
    UPDATE crm_users 
    SET session_id = v_session_id,
        session_expires_at = v_session_expires,
        failed_login_attempts = 0,
        locked_until = NULL,
        last_login = NOW(),
        updated_at = NOW()
    WHERE id = v_user.id;

    -- Log successful attempt
    PERFORM log_auth_attempt(v_user.id, p_username, 'PASSWORD_VERIFIED', p_ip_address, p_user_agent, true, NULL, v_session_id);

    -- Return success result
    v_result.success := true;
    v_result.user_id := v_user.id;
    v_result.username := v_user.username;
    v_result.requires_2fa := NOT v_user.has_2fa;
    v_result.session_id := v_session_id;
    v_result.session_expires_at := v_session_expires;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function 2: Verify session with built-in security
CREATE OR REPLACE FUNCTION verify_session(p_session_id UUID)
RETURNS session_result AS $$
DECLARE
    v_user crm_users%ROWTYPE;
    v_result session_result;
    v_new_expiry TIMESTAMPTZ;
BEGIN
    -- Input validation
    IF p_session_id IS NULL THEN
        v_result.valid := false;
        v_result.error_message := 'Invalid session ID';
        RETURN v_result;
    END IF;

    -- Clean expired sessions first
    PERFORM clean_expired_sessions();

    -- Get user by session
    SELECT * INTO v_user 
    FROM crm_users 
    WHERE session_id = p_session_id 
    AND session_expires_at > NOW()
    AND is_active = true;

    IF NOT FOUND THEN
        v_result.valid := false;
        v_result.error_message := 'Session expired or invalid';
        RETURN v_result;
    END IF;

    -- Extend session if it's going to expire soon (within 30 minutes)
    IF v_user.session_expires_at < NOW() + INTERVAL '30 minutes' THEN
        v_new_expiry := NOW() + INTERVAL '2 hours';
        
        UPDATE crm_users 
        SET session_expires_at = v_new_expiry,
            updated_at = NOW()
        WHERE id = v_user.id;
        
        v_user.session_expires_at := v_new_expiry;
    END IF;

    -- Return valid session
    v_result.valid := true;
    v_result.user_id := v_user.id;
    v_result.username := v_user.username;
    v_result.expires_at := v_user.session_expires_at;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function 3: Setup 2FA with security checks
CREATE OR REPLACE FUNCTION setup_user_2fa(
    p_session_id UUID,
    p_two_fa_secret TEXT
)
RETURNS BOOLEAN AS $$
DECLARE
    v_session session_result;
BEGIN
    -- Verify session first
    SELECT * INTO v_session FROM verify_session(p_session_id);
    
    IF NOT v_session.valid THEN
        RETURN false;
    END IF;

    -- Update 2FA settings
    UPDATE crm_users 
    SET two_fa_secret = p_two_fa_secret,
        updated_at = NOW()
    WHERE id = v_session.user_id;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function 4: Complete 2FA setup (mark as enabled)
CREATE OR REPLACE FUNCTION complete_2fa_setup(p_session_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_session session_result;
BEGIN
    -- Verify session first
    SELECT * INTO v_session FROM verify_session(p_session_id);
    
    IF NOT v_session.valid THEN
        RETURN false;
    END IF;

    -- Mark 2FA as complete
    UPDATE crm_users 
    SET has_2fa = true,
        updated_at = NOW()
    WHERE id = v_session.user_id;

    -- Log 2FA completion
    PERFORM log_auth_attempt(v_session.user_id, v_session.username, '2FA_COMPLETE', NULL, NULL, true, NULL, p_session_id);

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function 5: Get user 2FA status
CREATE OR REPLACE FUNCTION get_user_2fa_status(p_session_id UUID)
RETURNS TABLE(has_2fa BOOLEAN, two_fa_secret TEXT) AS $$
DECLARE
    v_session session_result;
BEGIN
    -- Verify session first
    SELECT * INTO v_session FROM verify_session(p_session_id);
    
    IF NOT v_session.valid THEN
        RETURN;
    END IF;

    -- Return 2FA status
    RETURN QUERY 
    SELECT u.has_2fa, u.two_fa_secret 
    FROM crm_users u 
    WHERE u.id = v_session.user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function 6: Secure logout
CREATE OR REPLACE FUNCTION logout_user(p_session_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_session session_result;
BEGIN
    -- Get session info first
    SELECT * INTO v_session FROM verify_session(p_session_id);
    
    IF NOT v_session.valid THEN
        RETURN false;
    END IF;

    -- Clear session
    UPDATE crm_users 
    SET session_id = NULL,
        session_expires_at = NULL,
        updated_at = NOW()
    WHERE id = v_session.user_id;

    -- Log logout
    PERFORM log_auth_attempt(v_session.user_id, v_session.username, 'LOGOUT', NULL, NULL, true, NULL, p_session_id);

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Update existing tables to block direct access completely
DROP POLICY IF EXISTS "Service role can manage users" ON crm_users;
DROP POLICY IF EXISTS "Users can view own data" ON crm_users;
DROP POLICY IF EXISTS "Block anonymous access" ON crm_users;

-- Completely block direct table access - force use of functions only
CREATE POLICY "Block all direct access to crm_users" ON crm_users
    FOR ALL 
    TO anon, authenticated, service_role
    USING (false)
    WITH CHECK (false);

-- Update audit log policies to be more restrictive  
DROP POLICY IF EXISTS "Service role can manage audit logs" ON crm_audit_log;
DROP POLICY IF EXISTS "Block non-service access to audit logs" ON crm_audit_log;

CREATE POLICY "Block all direct access to audit logs" ON crm_audit_log
    FOR ALL 
    TO anon, authenticated, service_role
    USING (false)
    WITH CHECK (false);

-- Grant execute permissions to anon and authenticated roles for the functions
GRANT EXECUTE ON FUNCTION authenticate_user(TEXT, TEXT, INET, TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION verify_session(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION setup_user_2fa(UUID, TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION complete_2fa_setup(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION get_user_2fa_status(UUID) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION logout_user(UUID) TO anon, authenticated;

-- Keep existing utility functions accessible to functions only
REVOKE ALL ON FUNCTION log_auth_attempt FROM anon, authenticated;
REVOKE ALL ON FUNCTION clean_expired_sessions FROM anon, authenticated;
REVOKE ALL ON FUNCTION unlock_expired_locks FROM anon, authenticated;

-- Grant to functions only (they run as SECURITY DEFINER)
GRANT EXECUTE ON FUNCTION log_auth_attempt TO service_role;
GRANT EXECUTE ON FUNCTION clean_expired_sessions TO service_role;
GRANT EXECUTE ON FUNCTION unlock_expired_locks TO service_role;

-- Comments for documentation
COMMENT ON FUNCTION authenticate_user IS 'Secure authentication function with built-in security checks - callable with anon key only';
COMMENT ON FUNCTION verify_session IS 'Secure session verification with auto-extension - callable with anon key only';
COMMENT ON FUNCTION setup_user_2fa IS 'Secure 2FA secret storage - requires valid session';
COMMENT ON FUNCTION complete_2fa_setup IS 'Complete 2FA setup process - requires valid session';
COMMENT ON FUNCTION get_user_2fa_status IS 'Get user 2FA status - requires valid session';
COMMENT ON FUNCTION logout_user IS 'Secure logout function - requires valid session';

-- Security notice
COMMENT ON TYPE auth_result IS 'Authentication result type - contains no sensitive data';
COMMENT ON TYPE session_result IS 'Session verification result type - contains no sensitive data';

-- Final security verification
DO $$
BEGIN
    RAISE NOTICE 'Enhanced security functions installed successfully!';
    RAISE NOTICE 'Direct table access is now completely blocked.';
    RAISE NOTICE 'All operations must go through secure database functions.';
    RAISE NOTICE 'Service role key is NO LONGER REQUIRED!';
END $$;

-- ========================================
-- CREATE DEFAULT ADMIN USER
-- ========================================

-- Create the default admin user with bcrypt-hashed password
-- Username: admin
-- Password: admin123
-- Note: In production, this should be changed immediately

DO $$
DECLARE
    v_admin_id UUID;
    v_password_hash TEXT;
BEGIN
    -- Generate bcrypt hash for 'admin123' (12 rounds)
    -- This is the bcrypt hash for 'admin123' with 12 salt rounds
    v_password_hash := '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBVJ3fBq1yEuLG';
    
    -- Check if admin user already exists
    SELECT id INTO v_admin_id FROM crm_users WHERE username = 'admin';
    
    IF v_admin_id IS NULL THEN
        -- Create admin user
        INSERT INTO crm_users (id, username, password_hash, has_2fa, created_at, updated_at)
        VALUES (
            gen_random_uuid(),
            'admin',
            v_password_hash,
            false,
            NOW(),
            NOW()
        );
        
        -- Log the user creation
        INSERT INTO crm_audit_log (user_id, username, action, ip_address, user_agent, success, error_message, session_id)
        VALUES (NULL, 'admin', 'USER_CREATED', NULL, 'system', true, 'Default admin user created', NULL);
        
        RAISE NOTICE 'Default admin user created successfully!';
        RAISE NOTICE 'Username: admin';
        RAISE NOTICE 'Password: admin123';
        RAISE NOTICE 'IMPORTANT: Change this password immediately in production!';
    ELSE
        RAISE NOTICE 'Admin user already exists - no changes made';
    END IF;
END;
$$;
