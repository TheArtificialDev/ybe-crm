import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify, SignJWT } from 'jose'
import { AuthService } from '@/lib/auth-service'

export async function POST(request: NextRequest) {
  try {
    const { token: userToken } = await request.json()
    const authToken = request.cookies.get('auth-token')?.value

    if (!authToken) {
      return NextResponse.json(
        { error: 'Not authenticated' },
        { status: 401 }
      )
    }

    if (!userToken || userToken.length !== 6) {
      return NextResponse.json(
        { error: 'Invalid token format' },
        { status: 400 }
      )
    }

    // Verify auth token
    const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'fallback-secret')
    const { payload } = await jwtVerify(authToken, secret)
    
    const sessionId = payload.sessionId as string
    if (!sessionId) {
      return NextResponse.json(
        { error: 'Invalid session' },
        { status: 401 }
      )
    }

    // Get client info for security logging
    const ipAddress = AuthService.getClientIP(request)
    const userAgent = request.headers.get('user-agent') || undefined

    // Verify 2FA token using secure database function
    const result = await AuthService.verify2FA(sessionId, userToken, ipAddress, userAgent)

    if (!result.success) {
      return NextResponse.json(
        { error: result.error },
        { status: 401 }
      )
    }

    // Create final authenticated session token
    const finalToken = await new SignJWT({ 
      userId: result.user!.id, 
      username: result.user!.username,
      sessionId: result.sessionId,
      step: 'fully-authenticated'
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('2h') // Match session duration
      .sign(secret)

    const response = NextResponse.json({ success: true })
    response.cookies.set('auth-token', finalToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7200 // 2 hours to match session
    })

    return response
  } catch (error) {
    console.error('2FA verification error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
