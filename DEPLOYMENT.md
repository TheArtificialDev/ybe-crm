# 🚀 CRM Deployment Checklist - Fortress Security Edition

## ✅ Pre-Deployment Verification

### Database Setup
- [ ] **Execute SQL Script**: Run `supabase-security-functions.sql` in Supabase SQL editor
- [ ] **Verify Functions**: Confirm all SECURITY DEFINER functions are created
- [ ] **Test Default User**: Verify admin/admin123 credentials work
- [ ] **Check RLS Policies**: Ensure Row Level Security is enabled on all tables
- [ ] **Verify Tables**: Confirm all CRM tables are created with proper constraints

### Environment Configuration
- [ ] **Supabase URL**: Set `NEXT_PUBLIC_SUPABASE_URL` correctly
- [ ] **Anon Key**: Set `NEXT_PUBLIC_SUPABASE_ANON_KEY` (NOT service role)
- [ ] **JWT Secrets**: Generate strong random `JWT_SECRET` and `JWT_REFRESH_SECRET`
- [ ] **App Configuration**: Set `NEXT_PUBLIC_APP_NAME` and `NEXT_PUBLIC_APP_URL`
- [ ] **Remove Service Role**: Confirm no `SUPABASE_SERVICE_ROLE_KEY` in production

### Security Verification
- [ ] **Build Success**: `npm run build` completes without errors
- [ ] **Login Flow**: Test complete authentication flow
- [ ] **2FA Setup**: Verify QR code generation and TOTP validation
- [ ] **Account Lockout**: Test failed attempt protection
- [ ] **Session Management**: Confirm 2-hour session expiry
- [ ] **Audit Logging**: Check security events are logged

## 🔐 Production Security Steps

### 1. Database Security Functions
```sql
-- Verify these functions exist in Supabase:
SELECT routine_name, security_type 
FROM information_schema.routines 
WHERE routine_schema = 'public' 
AND routine_name LIKE '%user%';

-- Expected functions with SECURITY DEFINER:
-- - authenticate_user
-- - setup_user_2fa  
-- - complete_2fa_setup
-- - verify_2fa
-- - verify_session
-- - logout_user
-- - cleanup_expired_sessions
```

### 2. Environment Variables (Production)

**Vercel Dashboard Configuration:**
```bash
# Supabase (CRITICAL: Use anon key only)
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key

# JWT Security (CRITICAL: Use strong random values)
JWT_SECRET=your_super_strong_jwt_secret_at_least_32_characters_long
JWT_REFRESH_SECRET=your_different_strong_refresh_secret_32_chars_plus

# App Configuration
NEXT_PUBLIC_APP_NAME="Y-Be CRM"
NEXT_PUBLIC_APP_URL=https://crm.y-be.tech
```

**Generate Strong Secrets:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

### 3. Vercel Deployment

**Commands:**
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy to production
vercel --prod

# Set custom domain
vercel domains add crm.y-be.tech
```

### 4. Post-Deployment Testing

**Security Test Checklist:**
- [ ] **Login Page**: Accessible at https://crm.y-be.tech
- [ ] **Failed Attempts**: Test account lockout after 5 failures
- [ ] **2FA Setup**: QR code generation works correctly
- [ ] **Session Expiry**: Automatic logout after 2 hours
- [ ] **IP Tracking**: Verify client IP logging in audit table
- [ ] **Database Security**: Confirm anon key cannot access tables directly

**Test Commands:**
```bash
# Test API endpoints
curl -X POST https://crm.y-be.tech/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Verify database security (should fail)
curl -X GET "https://your-project.supabase.co/rest/v1/crm_users" \
  -H "Authorization: Bearer your_anon_key"
```

## 🛡️ Security Validation

### Database Function Security
```sql
-- Test with anon role (should work)
SELECT authenticate_user('admin', 'admin123', '127.0.0.1', 'test-agent');

-- Test direct table access with anon (should fail)
SELECT * FROM crm_users;
```

### Session Security Test
```sql
-- Check active sessions
SELECT u.username, s.session_id, s.expires_at, s.ip_address
FROM crm_users u
JOIN crm_user_sessions s ON u.id = s.user_id
WHERE s.expires_at > NOW();

-- Check audit logs
SELECT action, success, ip_address, created_at
FROM crm_audit_log
ORDER BY created_at DESC
LIMIT 10;
```

## 🎯 Production Monitoring

### Health Checks
- [ ] **Login Success Rate**: Monitor authentication success/failure ratio
- [ ] **Session Duration**: Track average session lengths
- [ ] **Failed Attempts**: Monitor lockout frequency
- [ ] **2FA Usage**: Verify 2FA compliance
- [ ] **API Response Times**: Monitor authentication endpoint performance

### Alerting Setup
- [ ] **Failed Login Spikes**: Alert on unusual failure patterns
- [ ] **Account Lockouts**: Notify on lockout events
- [ ] **System Errors**: Monitor authentication system health
- [ ] **Session Anomalies**: Track unusual session patterns

## 🔄 Maintenance Tasks

### Weekly
- [ ] **Review Audit Logs**: Check for security anomalies
- [ ] **Session Cleanup**: Verify automatic cleanup is working
- [ ] **Performance Monitoring**: Check authentication response times

### Monthly  
- [ ] **Security Review**: Analyze authentication patterns
- [ ] **User Management**: Review active user accounts
- [ ] **Database Optimization**: Check query performance

### Quarterly
- [ ] **Security Audit**: Comprehensive security review
- [ ] **Password Policy**: Review and update as needed
- [ ] **2FA Compliance**: Ensure all users have 2FA enabled

## 🆘 Emergency Procedures

### Account Recovery
```sql
-- Reset user lockout (emergency access)
DELETE FROM crm_account_lockouts WHERE user_id = (
  SELECT id FROM crm_users WHERE username = 'admin'
);

-- Force password reset (if needed)
UPDATE crm_users 
SET password_hash = '$2a$12$new_hash_here'
WHERE username = 'admin';
```

### System Recovery
```sql
-- Clear all sessions (emergency logout all users)
DELETE FROM crm_user_sessions WHERE expires_at > NOW();

-- Check system health
SELECT 
  (SELECT COUNT(*) FROM crm_users) as total_users,
  (SELECT COUNT(*) FROM crm_user_sessions WHERE expires_at > NOW()) as active_sessions,
  (SELECT COUNT(*) FROM crm_account_lockouts WHERE locked_until > NOW()) as locked_accounts;
```

## ✅ Final Deployment Sign-off

**Project Manager Approval:**
- [ ] All security features tested and working
- [ ] Database functions deployed and verified
- [ ] Environment variables configured securely
- [ ] No service role key in production environment
- [ ] Audit logging operational
- [ ] Session management working correctly

**Technical Lead Approval:**
- [ ] Code review completed
- [ ] Security architecture verified
- [ ] Performance benchmarks met
- [ ] Monitoring and alerting configured
- [ ] Emergency procedures documented

**Security Team Approval:**
- [ ] Penetration testing completed
- [ ] Vulnerability assessment passed
- [ ] Compliance requirements met
- [ ] Incident response procedures ready

---

**🔒 Fortress Security Deployment Complete**
*Y-Be CRM is ready for production with maximum security*

**Default Credentials (CHANGE IMMEDIATELY):**
- Username: admin
- Password: admin123
- 2FA: Setup required on first login

**Critical Security Reminder:**
🚨 **NO SERVICE ROLE KEY IN PRODUCTION** 🚨
All security is enforced at the database function level!
