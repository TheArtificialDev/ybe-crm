import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import { AuthService } from '@/lib/auth-service'

export async function POST(request: NextRequest) {
  try {
    const authToken = request.cookies.get('auth-token')?.value

    if (!authToken) {
      return NextResponse.json({ success: true }) // Already logged out
    }

    // Try to extract session ID from token
    try {
      const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'fallback-secret')
      const { payload } = await jwtVerify(authToken, secret)
      
      const sessionId = payload.sessionId as string
      if (sessionId) {
        // Get client info for security logging
        const ipAddress = AuthService.getClientIP(request)
        const userAgent = request.headers.get('user-agent') || undefined

        // Logout using secure database function
        await AuthService.logout(sessionId, ipAddress, userAgent)
      }
    } catch (error) {
      // Token invalid/expired, continue with logout anyway
      console.log('Token verification failed during logout:', error)
    }

    // Clear auth cookie
    const response = NextResponse.json({ success: true })
    response.cookies.set('auth-token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0 // Immediately expire
    })

    return response
  } catch (error) {
    console.error('Logout error:', error)
    
    // Even if logout fails, clear the cookie
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
