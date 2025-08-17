import bcrypt from 'bcryptjs'
import speakeasy from 'speakeasy'
import { v4 as uuidv4 } from 'uuid'
import { supabaseAdmin, type AuthUser } from './supabase'

// Security configuration
const SECURITY_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION_MINUTES: 30,
  SESSION_DURATION_HOURS: 2, // Force re-login every 2 hours
  PASSWORD_MIN_LENGTH: 8,
  REQUIRE_2FA: true,
  SESSION_CLEANUP_INTERVAL: 300000, // 5 minutes
} as const

export interface LoginResult {
  success: boolean
  user?: Partial<AuthUser>
  sessionId?: string
  requiresSetup2FA?: boolean
  error?: string
  isLocked?: boolean
  lockoutMinutes?: number
}

export interface VerifyTokenResult {
  success: boolean
  user?: Partial<AuthUser>
  sessionId?: string
  error?: string
}

export class AuthService {
  
  /**
   * Authenticate user with username and password
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
        await this.logAuthAttempt(null, username, 'LOGIN_ATTEMPT', ipAddress, userAgent, false, 'Missing credentials')
        return { success: false, error: 'Username and password are required' }
      }

      // Clean up expired sessions and locks first
      await this.cleanupExpiredSessions()
      await this.unlockExpiredAccounts()

      // Get user from database
      const { data: user, error } = await supabaseAdmin
        .from('auth_users')
        .select('*')
        .eq('username', username)
        .eq('is_active', true)
        .single()

      if (error || !user) {
        await this.logAuthAttempt(null, username, 'LOGIN_ATTEMPT', ipAddress, userAgent, false, 'User not found')
        return { success: false, error: 'Invalid credentials' }
      }

      // Check if account is locked
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        const lockoutMinutes = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60000)
        await this.logAuthAttempt(user.id, username, 'LOGIN_BLOCKED', ipAddress, userAgent, false, 'Account locked')
        return { 
          success: false, 
          error: 'Account is temporarily locked due to multiple failed attempts',
          isLocked: true,
          lockoutMinutes
        }
      }

      // Verify password
      const passwordMatch = await bcrypt.compare(password, user.password_hash)
      
      if (!passwordMatch) {
        // Increment failed attempts
        const newFailedAttempts = user.failed_login_attempts + 1
        let lockUntil = null
        
        if (newFailedAttempts >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
          lockUntil = new Date(Date.now() + SECURITY_CONFIG.LOCKOUT_DURATION_MINUTES * 60000).toISOString()
        }

        await supabaseAdmin
          .from('auth_users')
          .update({
            failed_login_attempts: newFailedAttempts,
            locked_until: lockUntil,
            updated_at: new Date().toISOString()
          })
          .eq('id', user.id)

        await this.logAuthAttempt(user.id, username, 'LOGIN_FAILED', ipAddress, userAgent, false, 'Invalid password')
        
        if (lockUntil) {
          return { 
            success: false, 
            error: 'Account has been locked due to multiple failed attempts',
            isLocked: true,
            lockoutMinutes: SECURITY_CONFIG.LOCKOUT_DURATION_MINUTES
          }
        }

        return { success: false, error: 'Invalid credentials' }
      }

      // Reset failed attempts on successful password verification
      await supabaseAdmin
        .from('auth_users')
        .update({
          failed_login_attempts: 0,
          locked_until: null,
          last_login: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', user.id)

      await this.logAuthAttempt(user.id, username, 'PASSWORD_VERIFIED', ipAddress, userAgent, true)

      // Check if 2FA setup is required
      if (!user.has_2fa) {
        return {
          success: true,
          user: { id: user.id, username: user.username },
          requiresSetup2FA: true
        }
      }

      // Return success (still need 2FA verification)
      return {
        success: true,
        user: { id: user.id, username: user.username, has_2fa: user.has_2fa }
      }

    } catch (error) {
      console.error('Authentication error:', error)
      await this.logAuthAttempt(null, username, 'LOGIN_ERROR', ipAddress, userAgent, false, 'System error')
      return { success: false, error: 'Authentication system error' }
    }
  }

  /**
   * Setup 2FA for user
   */
  static async setup2FA(userId: string): Promise<{ secret: string; qrCode: string } | null> {
    try {
      const user = await this.getUserById(userId)
      if (!user) return null

      // Generate new secret
      const secret = speakeasy.generateSecret({
        name: `Y-Be.tech CRM (${user.username})`,
        issuer: 'Y-Be.tech',
        length: 32
      })

      // Store secret temporarily (will be confirmed after verification)
      await supabaseAdmin
        .from('auth_users')
        .update({
          two_fa_secret: secret.base32,
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)

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
   * Verify 2FA token and create session
   */
  static async verify2FA(
    userId: string, 
    token: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<VerifyTokenResult> {
    try {
      const user = await this.getUserById(userId)
      if (!user) {
        await this.logAuthAttempt(userId, null, '2FA_FAILED', ipAddress, userAgent, false, 'User not found')
        return { success: false, error: 'User not found' }
      }

      if (!user.two_fa_secret) {
        await this.logAuthAttempt(userId, user.username, '2FA_FAILED', ipAddress, userAgent, false, 'No 2FA secret')
        return { success: false, error: '2FA not set up' }
      }

      // Verify token
      const verified = speakeasy.totp.verify({
        secret: user.two_fa_secret,
        encoding: 'base32',
        token: token,
        window: 1 // Allow 1 step before/after for clock skew
      })

      if (!verified) {
        await this.logAuthAttempt(userId, user.username, '2FA_FAILED', ipAddress, userAgent, false, 'Invalid token')
        return { success: false, error: 'Invalid verification code' }
      }

      // Generate session
      const sessionId = uuidv4()
      const sessionExpiry = new Date(Date.now() + SECURITY_CONFIG.SESSION_DURATION_HOURS * 60 * 60 * 1000)

      // Update user with session and mark 2FA as complete
      await supabaseAdmin
        .from('auth_users')
        .update({
          has_2fa: true,
          session_id: sessionId,
          session_expires_at: sessionExpiry.toISOString(),
          last_login: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)

      await this.logAuthAttempt(userId, user.username, '2FA_SUCCESS', ipAddress, userAgent, true, undefined, sessionId)

      return {
        success: true,
        user: { id: user.id, username: user.username },
        sessionId
      }
    } catch (error) {
      console.error('2FA verification error:', error)
      await this.logAuthAttempt(userId, null, '2FA_ERROR', ipAddress, userAgent, false, 'System error')
      return { success: false, error: '2FA verification system error' }
    }
  }

  /**
   * Validate session
   */
  static async validateSession(sessionId: string): Promise<AuthUser | null> {
    try {
      if (!sessionId) return null

      await this.cleanupExpiredSessions()

      const { data: user, error } = await supabaseAdmin
        .from('auth_users')
        .select('*')
        .eq('session_id', sessionId)
        .eq('is_active', true)
        .gte('session_expires_at', new Date().toISOString())
        .single()

      if (error || !user) return null

      // Extend session if it's going to expire soon (within 30 minutes)
      const expiryTime = new Date(user.session_expires_at!).getTime()
      const now = Date.now()
      const thirtyMinutes = 30 * 60 * 1000

      if (expiryTime - now < thirtyMinutes) {
        const newExpiry = new Date(now + SECURITY_CONFIG.SESSION_DURATION_HOURS * 60 * 60 * 1000)
        
        await supabaseAdmin
          .from('auth_users')
          .update({
            session_expires_at: newExpiry.toISOString(),
            updated_at: new Date().toISOString()
          })
          .eq('id', user.id)

        user.session_expires_at = newExpiry.toISOString()
      }

      return user
    } catch (error) {
      console.error('Session validation error:', error)
      return null
    }
  }

  /**
   * Invalidate session (logout)
   */
  static async invalidateSession(sessionId: string, ipAddress?: string, userAgent?: string): Promise<boolean> {
    try {
      const user = await this.validateSession(sessionId)
      
      const { error } = await supabaseAdmin
        .from('auth_users')
        .update({
          session_id: null,
          session_expires_at: null,
          updated_at: new Date().toISOString()
        })
        .eq('session_id', sessionId)

      if (user) {
        await this.logAuthAttempt(user.id, user.username, 'LOGOUT', ipAddress, userAgent, true, undefined, sessionId)
      }

      return !error
    } catch (error) {
      console.error('Session invalidation error:', error)
      return false
    }
  }

  /**
   * Get user by ID
   */
  static async getUserById(userId: string): Promise<AuthUser | null> {
    try {
      const { data: user, error } = await supabaseAdmin
        .from('auth_users')
        .select('*')
        .eq('id', userId)
        .eq('is_active', true)
        .single()

      return error ? null : user
    } catch (error) {
      console.error('Get user error:', error)
      return null
    }
  }

  /**
   * Log authentication attempt
   */
  static async logAuthAttempt(
    userId: string | null,
    username: string | null,
    action: string,
    ipAddress?: string,
    userAgent?: string,
    success: boolean = false,
    failureReason?: string,
    sessionId?: string
  ): Promise<void> {
    try {
      await supabaseAdmin.rpc('log_auth_attempt', {
        p_user_id: userId,
        p_username: username,
        p_action: action,
        p_ip_address: ipAddress,
        p_user_agent: userAgent,
        p_success: success,
        p_failure_reason: failureReason,
        p_session_id: sessionId
      })
    } catch (error) {
      console.error('Failed to log auth attempt:', error)
    }
  }

  /**
   * Clean up expired sessions
   */
  static async cleanupExpiredSessions(): Promise<void> {
    try {
      await supabaseAdmin.rpc('clean_expired_sessions')
    } catch (error) {
      console.error('Failed to clean expired sessions:', error)
    }
  }

  /**
   * Unlock expired account locks
   */
  static async unlockExpiredAccounts(): Promise<void> {
    try {
      await supabaseAdmin.rpc('unlock_expired_locks')
    } catch (error) {
      console.error('Failed to unlock expired accounts:', error)
    }
  }

  /**
   * Get client IP address from request
   */
  static getClientIP(request: Request): string {
    const forwarded = request.headers.get('x-forwarded-for')
    const real = request.headers.get('x-real-ip')
    const host = request.headers.get('host')
    
    if (forwarded) {
      return forwarded.split(',')[0].trim()
    }
    
    if (real) {
      return real
    }
    
    return host || 'unknown'
  }
}

// Schedule periodic cleanup (in a real app, this would be handled by a cron job)
if (typeof window === 'undefined') {
  setInterval(() => {
    AuthService.cleanupExpiredSessions()
    AuthService.unlockExpiredAccounts()
  }, SECURITY_CONFIG.SESSION_CLEANUP_INTERVAL)
}
