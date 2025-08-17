import bcrypt from 'bcryptjs'
import speakeasy from 'speakeasy'
import { v4 as uuidv4 } from 'uuid'
import { NextRequest } from 'next/server'
import { supabase, type AuthResult, type SessionResult, type User2FAStatus } from './supabase'

// Security configuration
const SECURITY_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION_MINUTES: 30,
  SESSION_DURATION_HOURS: 2,
  PASSWORD_MIN_LENGTH: 8,
  REQUIRE_2FA: true,
  BCRYPT_ROUNDS: 12,
} as const

export interface LoginResult {
  success: boolean
  user?: { id: string; username: string }
  sessionId?: string
  requiresSetup2FA?: boolean
  error?: string
  isLocked?: boolean
  lockoutMinutes?: number
}

export interface VerifyTokenResult {
  success: boolean
  user?: { id: string; username: string }
  sessionId?: string
  error?: string
}

export class AuthService {
  
  /**
   * Authenticate user with username and password using secure database function
   */
  static async authenticateUser(
    username: string, 
    password: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<LoginResult> {
    try {
      // Input validation
      if (!username || !password) {
        return { success: false, error: 'Username and password are required' }
      }

      // Hash password for database comparison
      const hashedPassword = await bcrypt.hash(password, SECURITY_CONFIG.BCRYPT_ROUNDS)

      // Call secure database function with anon key
      const { data, error } = await supabase.rpc('authenticate_user', {
        p_username: username,
        p_password_hash: hashedPassword,
        p_ip_address: ipAddress || null,
        p_user_agent: userAgent || null
      })

      if (error) {
        console.error('Database authentication error:', error)
        return { success: false, error: 'Authentication service error' }
      }

      const result = data as AuthResult

      if (!result.success) {
        // Handle account lockout
        if (result.locked_until) {
          const lockoutMinutes = Math.ceil(
            (new Date(result.locked_until).getTime() - Date.now()) / 60000
          )
          return { 
            success: false, 
            error: result.error_message || 'Account locked',
            isLocked: true,
            lockoutMinutes: Math.max(0, lockoutMinutes)
          }
        }
        
        return { success: false, error: result.error_message || 'Authentication failed' }
      }

      // Success
      return {
        success: true,
        user: { id: result.user_id!, username: result.username! },
        sessionId: result.session_id,
        requiresSetup2FA: result.requires_2fa
      }

    } catch (error) {
      console.error('Authentication error:', error)
      return { success: false, error: 'Authentication system error' }
    }
  }

  /**
   * Setup 2FA for user using secure database function
   */
  static async setup2FA(sessionId: string): Promise<{ secret: string; qrCode: string } | null> {
    try {
      // Generate new secret
      const secret = speakeasy.generateSecret({
        name: 'Y-Be.tech CRM',
        issuer: 'Y-Be.tech',
        length: 32
      })

      // Store secret using secure database function
      const { data, error } = await supabase.rpc('setup_user_2fa', {
        p_session_id: sessionId,
        p_two_fa_secret: secret.base32
      })

      if (error || !data) {
        console.error('2FA setup error:', error)
        return null
      }

      return {
        secret: secret.base32,
        qrCode: secret.otpauth_url || ''
      }
    } catch (error) {
      console.error('2FA setup error:', error)
      return null
    }
  }

  /**
   * Get user 2FA status using secure database function
   */
  static async get2FAStatus(sessionId: string): Promise<User2FAStatus | null> {
    try {
      const { data, error } = await supabase.rpc('get_user_2fa_status', {
        p_session_id: sessionId
      })

      if (error || !data || data.length === 0) {
        return null
      }

      return data[0] as User2FAStatus
    } catch (error) {
      console.error('2FA status check error:', error)
      return null
    }
  }

  /**
   * Verify 2FA token and complete setup if needed
   */
  static async verify2FA(
    sessionId: string, 
    token: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<VerifyTokenResult> {
    try {
      // Get user 2FA status
      const status = await this.get2FAStatus(sessionId)
      if (!status || !status.two_fa_secret) {
        return { success: false, error: '2FA not set up' }
      }

      // Verify token
      const verified = speakeasy.totp.verify({
        secret: status.two_fa_secret,
        encoding: 'base32',
        token: token,
        window: 1 // Allow 1 step before/after for clock skew
      })

      if (!verified) {
        return { success: false, error: 'Invalid verification code' }
      }

      // Complete 2FA setup if this is the first verification
      if (!status.has_2fa) {
        const { data, error } = await supabase.rpc('complete_2fa_setup', {
          p_session_id: sessionId
        })

        if (error || !data) {
          return { success: false, error: '2FA completion failed' }
        }
      }

      // Verify session is still valid
      const sessionResult = await this.validateSession(sessionId)
      if (!sessionResult) {
        return { success: false, error: 'Session expired' }
      }

      return {
        success: true,
        user: { id: sessionResult.user_id!, username: sessionResult.username! },
        sessionId
      }
    } catch (error) {
      console.error('2FA verification error:', error)
      return { success: false, error: '2FA verification system error' }
    }
  }

    /**
   * Validate an existing session
   */
  static async validateSession(sessionId: string): Promise<SessionResult | null> {
    try {
      const { data, error } = await supabase
        .rpc('verify_session', {
          p_session_id: sessionId
        })

      if (error) {
        console.error('Session validation error:', error)
        return null
      }

      if (!data || data.length === 0) {
        return null
      }

      const sessionData = data[0]
      return {
        valid: sessionData.is_valid,
        user_id: sessionData.is_valid ? sessionData.user_id : undefined,
        username: sessionData.is_valid ? sessionData.username : undefined,
        expires_at: sessionData.is_valid ? sessionData.expires_at : undefined
      }
    } catch (error) {
      console.error('Session validation error:', error)
      return null
    }
  }

  /**
   * Invalidate session (logout) using secure database function
   */
  static async invalidateSession(sessionId: string): Promise<boolean> {
    try {
      const { data, error } = await supabase.rpc('logout_user', {
        p_session_id: sessionId
      })

      if (error) {
        console.error('Session invalidation error:', error)
        return false
      }

      return data as boolean
    } catch (error) {
      console.error('Session invalidation error:', error)
      return false
    }
  }

  /**
   * Logout and invalidate session
   */
  static async logout(sessionId: string, ipAddress?: string, userAgent?: string): Promise<void> {
    try {
      await supabase
        .rpc('logout_user', {
          p_session_id: sessionId,
          p_ip_address: ipAddress,
          p_user_agent: userAgent
        })
    } catch (error) {
      console.error('Logout error:', error)
      // Don't throw - logout should always succeed from client perspective
    }
  }

  /**
   * Get client IP address from request headers
   */
  static getClientIP(request: NextRequest): string | undefined {
    const forwarded = request.headers.get('x-forwarded-for')
    const realIp = request.headers.get('x-real-ip')
    const remoteAddr = request.headers.get('remote-addr')
    
    if (forwarded) {
      return forwarded.split(',')[0].trim()
    }
    
    return realIp || remoteAddr || undefined
  }

  /**
   * Generate a strong JWT secret
   */
  static generateJWTSecret(): string {
    return uuidv4() + uuidv4().replace(/-/g, '')
  }
}
