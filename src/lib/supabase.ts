import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
// Use anon key only - all security enforced at database function level
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error('Missing Supabase environment variables')
}

// Secure client using anon key with database-level security
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
})

// Database types for secure function responses
export interface AuthResult {
  success: boolean
  user_id?: string
  username?: string
  requires_2fa?: boolean
  session_id?: string
  session_expires_at?: string
  error_message?: string
  locked_until?: string
}

export interface SessionResult {
  valid: boolean
  user_id?: string
  username?: string
  expires_at?: string
  error_message?: string
}

export interface User2FAStatus {
  has_2fa: boolean
  two_fa_secret: string | null
}
