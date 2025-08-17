import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import { AuthService } from '@/lib/auth-service'

export async function GET(request: NextRequest) {
  try {
    const token = request.cookies.get('auth-token')?.value

    if (!token) {
      return NextResponse.json(
        { error: 'Not authenticated' },
        { status: 401 }
      )
    }

    // Verify token
    const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'fallback-secret')
    const { payload } = await jwtVerify(token, secret)
    
    // Check if user is fully authenticated (passed 2FA)
    if (payload.step !== 'fully-authenticated') {
      return NextResponse.json(
        { error: 'Authentication not complete' },
        { status: 401 }
      )
    }

    const sessionId = payload.sessionId as string
    if (!sessionId) {
      return NextResponse.json(
        { error: 'No session found' },
        { status: 401 }
      )
    }

    // Validate session in database
    const user = await AuthService.validateSession(sessionId)
    if (!user) {
      return NextResponse.json(
        { error: 'Session expired or invalid' },
        { status: 401 }
      )
    }

    return NextResponse.json({
      userId: user.id,
      username: user.username,
      authenticated: true,
      sessionExpiresAt: user.session_expires_at
    })
  } catch (error) {
    console.error('Auth check error:', error)
    return NextResponse.json(
      { error: 'Invalid token' },
      { status: 401 }
    )
  }
}
