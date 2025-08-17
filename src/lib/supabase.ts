import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('Missing Supabase environment variables')
}

// Service role client for server-side operations
export const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
})

// Database types
export interface AuthUser {
  id: string
  username: string
  password_hash: string
  is_active: boolean
  has_2fa: boolean
  two_fa_secret: string | null
  failed_login_attempts: number
  locked_until: string | null
  last_login: string | null
  last_password_change: string
  session_id: string | null
  session_expires_at: string | null
  created_at: string
  updated_at: string
}

export interface AuthAuditLog {
  id: string
  user_id: string | null
  username: string | null
  action: string
  ip_address: string | null
  user_agent: string | null
  success: boolean
  failure_reason: string | null
  session_id: string | null
  created_at: string
}
