import { NextRequest, NextResponse } from 'next/server'
import { SignJWT } from 'jose'
import { AuthService } from '@/lib/auth-service'

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json()

    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400 }
      )
    }

    // Get client info for security logging
    const ipAddress = AuthService.getClientIP(request)
    const userAgent = request.headers.get('user-agent') || undefined

    // Authenticate user using secure database function
    const result = await AuthService.authenticateUser(username, password, ipAddress, userAgent)

    if (!result.success) {
      return NextResponse.json(
        { 
          error: result.error,
          isLocked: result.isLocked,
          lockoutMinutes: result.lockoutMinutes
        },
        { status: 401 }
      )
    }

    // Create temporary auth token for 2FA flow
    const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'fallback-secret')
    const token = await new SignJWT({ 
      userId: result.user!.id, 
      username: result.user!.username,
      sessionId: result.sessionId,
      step: result.requiresSetup2FA ? 'needs-2fa-setup' : 'needs-2fa-verification'
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('15m') // Short-lived token for 2FA flow
      .sign(secret)

    const response = NextResponse.json({ 
      success: true,
      requiresSetup2FA: result.requiresSetup2FA
    })
    
    response.cookies.set('auth-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 900 // 15 minutes
    })

    return response
  } catch (error) {
    console.error('Login error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
