import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import { AuthService } from '@/lib/auth-service'

export async function POST(request: NextRequest) {
  try {
    const token = request.cookies.get('auth-token')?.value
    
    if (token) {
      try {
        // Verify token to get session info
        const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'fallback-secret')
        const { payload } = await jwtVerify(token, secret)
        
        const sessionId = payload.sessionId as string
        if (sessionId) {
          // Get client info for security logging
          const ipAddress = AuthService.getClientIP(request)
          const userAgent = request.headers.get('user-agent') || undefined
          
          // Invalidate session in database
          await AuthService.invalidateSession(sessionId, ipAddress, userAgent)
        }
      } catch (error) {
        // Token might be invalid, but we still want to clear the cookie
        console.error('Error during logout:', error)
      }
    }

    const response = NextResponse.json({ success: true })
    
    // Clear the auth token cookie
    response.cookies.set('auth-token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0 // Expire immediately
    })

    return response
  } catch (error) {
    console.error('Logout error:', error)
    
    // Even if there's an error, clear the cookie
    const response = NextResponse.json({ success: true })
    response.cookies.set('auth-token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0
    })
    
    return response
  }
}
