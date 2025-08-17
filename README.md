# Y-Be.tech CRM

A secure internal CRM tool built with Next.js, featuring strong authentication with mandatory 2FA and Supabase integration.

## Features

- ✅ **Secure Authentication**: Username/password with comprehensive security
- ✅ **Mandatory 2FA**: TOTP authenticator app integration with QR setup
- ✅ **Account Security**: Failed attempt tracking and automatic lockouts
- ✅ **Session Management**: 2-hour sessions with automatic expiry
- ✅ **Supabase Integration**: Secure database with Row Level Security
- ✅ **Audit Logging**: Complete security event logging
- ✅ **Vercel Deployment Ready**: Optimized for production deployment

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Supabase project setup
- An authenticator app (Google Authenticator, Authy, etc.)

### Installation

1. **Install dependencies:**
```bash
npm install
```

2. **Configure Environment:**
```bash
cp .env.example .env.local
```

Edit `.env.local` with your Supabase credentials:

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
JWT_SECRET=your_very_strong_jwt_secret_at_least_32_chars
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

1. **Login**: Username/password validation
2. **Account Security**: Lockout after 5 failed attempts (30 minutes)
3. **2FA Setup**: QR code generation for authenticator apps
4. **2FA Verification**: 6-digit code validation
5. **Session Creation**: Secure session with 2-hour expiry
6. **Dashboard Access**: Protected application interface

### Default Credentials

⚠️ **CHANGE IN PRODUCTION!**
- **Username:** `admin`
- **Password:** `admin123`
- **2FA:** Setup required on first login

## Deployment

### Vercel Deployment

1. **Connect repository to Vercel**
2. **Set environment variables in Vercel dashboard:**
   ```env
   NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
   JWT_SECRET=your_very_strong_jwt_secret
   ```
3. **Deploy**

## Security Features

- **Account Lockout**: 5 failed attempts = 30-minute lockout
- **Session Security**: 2-hour maximum session duration
- **Password Hashing**: Bcrypt with 12 salt rounds
- **2FA Required**: Mandatory for all users
- **Audit Logging**: All authentication events logged
- **Row Level Security**: Database-level access control

## Project Structure

```
src/
├── app/
│   ├── api/auth/              # Authentication APIs
│   ├── auth/verify-2fa/       # 2FA verification page
│   ├── dashboard/             # Protected dashboard
│   └── page.tsx              # Login page
├── lib/
│   ├── auth-service.ts       # Authentication service
│   └── supabase.ts          # Supabase client
└── middleware.ts             # Route protection
```

## License

Internal use only - Y-Be.tech
