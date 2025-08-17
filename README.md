# Y-Be.tech CRM - Fortress Security Edition

An ultra-secure internal CRM tool built with Next.js, featuring fortress-level authentication with mandatory 2FA, Supabase integration, and comprehensive security monitoring.

## 🔒 Fortress Security Features

- **🛡️ Account Lockout Protection**: Automatic account lockout after 5 failed attempts for 30 minutes
- **⏰ Session Management**: Forced re-login every 2 hours with automatic session cleanup
- **🔐 Mandatory 2FA**: TOTP-based two-factor authentication required for all users
- **📊 Comprehensive Audit Logging**: All authentication attempts, successes, failures logged
- **🚫 No Signup Logic**: Read-only user authentication from secure database
- **🔍 IP & User Agent Tracking**: Enhanced security monitoring and logging
- **🔄 Session Validation**: Real-time session validation with database verification
- **🛠️ Automatic Cleanup**: Expired sessions and account locks automatically cleared

## Features

- ✅ **Fortress-Level Authentication**: Username/password with comprehensive security
- ✅ **Mandatory 2FA**: TOTP authenticator app integration with QR setup
- ✅ **Supabase Integration**: Secure user database with Row Level Security (RLS)
- ✅ **Session Management**: 2-hour sessions with automatic expiry and renewal
- ✅ **Account Security**: Failed attempt tracking and automatic lockouts
- ✅ **Audit Logging**: Complete security event logging and monitoring
- ✅ **JWT Security**: Secure session tokens with proper validation
- ✅ **Vercel Deployment Ready**: Optimized for production deployment
- 🔄 n8n workflow connections (coming soon)
- 🔄 Customer management interface (coming soon)

## Database Setup (Supabase)

### 1. Run the SQL Setup Script

Execute the provided `supabase-setup.sql` script in your Supabase SQL editor:

```sql
-- The script includes:
-- ✅ auth_users table with security features
-- ✅ auth_audit_log table for security monitoring  
-- ✅ Row Level Security (RLS) policies
-- ✅ Automatic cleanup functions
-- ✅ Security indexes and constraints
-- ✅ Default admin user (username: admin, password: admin123)
```

### 2. Security Features Included

- **Row Level Security**: Only service role can access user data
- **Account Lockout**: 5 failed attempts = 30-minute lockout
- **Session Tracking**: Real-time session validation and expiry
- **Audit Logging**: Complete authentication event history
- **Password Security**: Bcrypt hashing with salt rounds
- **2FA Integration**: Secure TOTP secret storage

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Supabase project with the SQL setup script executed
- An authenticator app (Google Authenticator, Authy, etc.)

### Installation

1. **Install dependencies:**
```bash
npm install
```

2. **Configure Supabase and Environment:**
```bash
cp .env.example .env.local
```

Edit `.env.local` with your **actual** Supabase credentials:

```env
# REQUIRED: Get these from your Supabase project settings
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

# REQUIRED: Generate a strong random string (32+ characters)
JWT_SECRET=your_very_strong_jwt_secret_at_least_32_chars

# App Configuration
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your_nextauth_secret
```

3. **Start the development server:**
```bash
npm run dev
```

4. **Access the application:**
   - Open [http://localhost:3000](http://localhost:3000)
   - Login with: `admin` / `admin123`
   - Set up 2FA when prompted

## Authentication Flow

### 🔒 Fortress Security Process

1. **Login Attempt**: Username/password validation with IP/UA logging
2. **Failed Attempt Tracking**: Automatic increment with lockout at 5 failures  
3. **Account Lockout**: 30-minute lockout after 5 failed attempts
4. **2FA Setup**: QR code generation for TOTP authenticator apps
5. **2FA Verification**: 6-digit code validation with time-based windows
6. **Session Creation**: Secure UUID session with 2-hour expiry
7. **Session Validation**: Real-time database session verification
8. **Automatic Cleanup**: Expired sessions and locks cleaned periodically

### Default Test Credentials

⚠️ **CHANGE BEFORE PRODUCTION!**
- **Username:** `admin`
- **Password:** `admin123`
- **2FA:** Set up on first login

## Security Configuration

### Database Security (Supabase)

- **Row Level Security (RLS)**: Enabled on all tables
- **Service Role Access**: Only service role can read/write user data
- **Anonymous Blocking**: Complete block on anonymous access
- **Audit Trail**: All auth attempts logged with IP/UA
- **Session Tracking**: Real-time session state management

### Application Security

- **Password Hashing**: Bcrypt with 12 salt rounds
- **JWT Tokens**: HS256 signed with secure secrets
- **HTTP-Only Cookies**: Secure session token storage
- **CSRF Protection**: SameSite cookie attributes
- **Session Limits**: 2-hour maximum session duration
- **IP Tracking**: Client IP logging for security monitoring

### Security Constants

```typescript
MAX_LOGIN_ATTEMPTS: 5           // Failed attempts before lockout
LOCKOUT_DURATION_MINUTES: 30   // Account lockout duration
SESSION_DURATION_HOURS: 2      // Maximum session length
REQUIRE_2FA: true              // Mandatory 2FA for all users
```

## Deployment on Vercel

### Production Deployment as `crm.y-be.tech`

1. **Connect repository to Vercel**
2. **Set environment variables in Vercel dashboard:**
   ```env
   NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
   SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
   JWT_SECRET=your_very_strong_jwt_secret
   NEXTAUTH_SECRET=your_nextauth_secret
   NEXTAUTH_URL=https://crm.y-be.tech
   ```
3. **Deploy and verify security features**

## Security Monitoring

### Audit Log Events

The system logs these security events:

- `LOGIN_ATTEMPT`: All login attempts (success/failure)
- `LOGIN_FAILED`: Failed password verification
- `LOGIN_BLOCKED`: Account lockout events
- `PASSWORD_VERIFIED`: Successful password verification
- `2FA_SUCCESS`: Successful 2FA verification
- `2FA_FAILED`: Failed 2FA attempts
- `LOGOUT`: User logout events
- `LOGIN_ERROR` / `2FA_ERROR`: System errors

### Monitoring Queries

```sql
-- Recent failed login attempts
SELECT * FROM auth_audit_log 
WHERE success = false AND action LIKE '%LOGIN%' 
ORDER BY created_at DESC LIMIT 50;

-- Account lockout events
SELECT * FROM auth_audit_log 
WHERE action = 'LOGIN_BLOCKED' 
ORDER BY created_at DESC;

-- Active sessions
SELECT username, session_expires_at, last_login 
FROM auth_users 
WHERE session_id IS NOT NULL;
```

## Project Structure

```
src/
├── app/
│   ├── api/auth/              # Fortress authentication APIs
│   │   ├── login/            # Secure login with lockout protection
│   │   ├── verify-2fa/       # 2FA verification with session creation
│   │   ├── check-2fa-setup/  # 2FA setup and QR generation
│   │   ├── me/               # Session validation endpoint
│   │   └── logout/           # Secure session termination
│   ├── auth/verify-2fa/       # 2FA verification interface
│   ├── dashboard/             # Protected dashboard
│   └── page.tsx              # Secure login page
├── lib/
│   ├── auth-service.ts       # Fortress authentication service
│   └── supabase.ts          # Secure Supabase client
├── middleware.ts             # Route protection middleware
└── supabase-setup.sql        # Database setup script
```

## Security Best Practices Implemented

### 🛡️ Authentication Security
- ✅ Password complexity validation
- ✅ Account lockout after failed attempts
- ✅ Secure password hashing (bcrypt)
- ✅ Mandatory 2FA for all users
- ✅ Session-based authentication
- ✅ IP address tracking

### 🔐 Session Security  
- ✅ Secure JWT token generation
- ✅ HTTP-only cookie storage
- ✅ Session expiry enforcement
- ✅ Real-time session validation
- ✅ Automatic session cleanup
- ✅ CSRF protection

### 📊 Monitoring & Logging
- ✅ Comprehensive audit logging
- ✅ Failed attempt tracking
- ✅ IP and User-Agent logging
- ✅ Security event timestamps
- ✅ Actionable security alerts

### 🗃️ Database Security
- ✅ Row Level Security (RLS)
- ✅ Service role isolation
- ✅ Encrypted data storage
- ✅ Secure connection handling
- ✅ SQL injection prevention

## Future Security Enhancements

- [ ] **Password Policy Enforcement**: Complexity requirements and aging
- [ ] **Rate Limiting**: API endpoint protection
- [ ] **Geolocation Tracking**: Location-based access controls
- [ ] **Device Fingerprinting**: Device recognition and management
- [ ] **Security Alerts**: Real-time notifications for suspicious activity
- [ ] **Backup 2FA Methods**: SMS and backup codes
- [ ] **Admin Security Dashboard**: Real-time security monitoring interface

## Contributing

This is a fortress-security internal tool for Y-Be.tech. All security practices must be maintained and enhanced.

## License

Internal use only - Y-Be.tech

---

⚠️ **Security Notice**: This application implements fortress-level security. Always change default credentials, use strong JWT secrets, and monitor audit logs regularly.
