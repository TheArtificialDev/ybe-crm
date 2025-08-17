# CRM Project Instructions

This is an internal CRM tool with Next.js, authentication, 2FA support, and Vercel deployment.

## Project Requirements
- Next.js with TypeScript
- Strong authentication with username/password
- Mandatory 2FA via authenticator app
- Dashboard after login
- Supabase for customer data storage
- n8n workflow connections
- Vercel deployment ready

## Features Implemented
- ✅ Strong login page with username/password authentication
- ✅ Mandatory 2FA support via authenticator app with QR code setup
- ✅ Protected dashboard accessible only after complete authentication
- ✅ Secure JWT-based session management
- ✅ Middleware-based route protection
- ✅ Vercel deployment configuration
- ✅ TypeScript and Tailwind CSS setup
- ✅ Fortress-level security with Supabase integration
- ✅ Account lockout protection (5 attempts = 30 min lockout)
- ✅ Session management with 2-hour forced re-login
- ✅ Comprehensive audit logging and security monitoring
- ✅ Real-time session validation with database verification
- ✅ IP address and User-Agent tracking for security
- ✅ Automatic cleanup of expired sessions and account locks

## Security Features
- 🔒 Account lockout after 5 failed attempts for 30 minutes
- ⏰ Forced re-login every 2 hours with automatic session cleanup
- 🛡️ Row Level Security (RLS) enabled on all Supabase tables
- 📊 Complete audit logging of all authentication events
- 🔐 Secure password hashing with bcrypt (12 salt rounds)
- 🚫 No signup logic - read-only authentication from database
- 🔍 IP address and User-Agent tracking for security monitoring

## Default Credentials
- Username: admin
- Password: admin123
- 2FA: Setup required on first login

## Database Setup
1. Execute the `supabase-setup.sql` script in your Supabase project
2. Configure environment variables with your Supabase credentials
3. The script creates secure tables with RLS and audit logging

## Next Steps
- Configure Supabase credentials in environment variables
- Implement customer management features
- Add n8n workflow integration
- Monitor security audit logs regularly

The project is ready for development and deployment with fortress-level security!
