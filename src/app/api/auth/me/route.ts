import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import { AuthService } from '@/lib/auth-service'

export async function GET(request: NextRequest) {
  try {
    const authToken = request.cookies.get('auth-token')?.value

    if (!authToken) {
      return NextResponse.json(
        { error: 'Not authenticated' },
        { status: 401 }
      )
    }

    // Verify JWT token
    const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'fallback-secret')
    const { payload } = await jwtVerify(authToken, secret)
    
    const sessionId = payload.sessionId as string
    if (!sessionId) {
      return NextResponse.json(
        { error: 'Invalid session' },
        { status: 401 }
      )
    }

    // Validate session using secure database function
    const result = await AuthService.validateSession(sessionId)

    if (!result || !result.valid) {
      return NextResponse.json(
        { error: result?.error_message || 'Session invalid' },
        { status: 401 }
      )
    }

    return NextResponse.json({
      user: {
        id: result.user_id!,
        username: result.username!
      }
    })
  } catch (error) {
    console.error('Profile fetch error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
