import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { jwtVerify } from 'jose'

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Public routes that don't require authentication
  const publicRoutes = [
    '/',
    '/api/auth/login',
    '/api/auth/check-2fa-setup',
    '/api/auth/verify-2fa'
  ]
  
  // Auth routes that require partial authentication
  const authRoutes = ['/auth/verify-2fa']
  
  // Protected routes that require full authentication
  const protectedRoutes = ['/dashboard']

  // API routes that require full authentication
  const protectedApiRoutes = ['/api/auth/me', '/api/auth/logout']

  // Allow public routes
  if (publicRoutes.includes(pathname)) {
    return NextResponse.next()
  }

  const token = request.cookies.get('auth-token')?.value

  // Redirect to login if no token for protected routes
  if (!token) {
    if (protectedRoutes.some(route => pathname.startsWith(route)) || 
        authRoutes.some(route => pathname.startsWith(route)) ||
        protectedApiRoutes.some(route => pathname.startsWith(route))) {
      if (pathname.startsWith('/api/')) {
        return NextResponse.json({ error: 'Not authenticated' }, { status: 401 })
      }
      return NextResponse.redirect(new URL('/', request.url))
    }
    return NextResponse.next()
  }

  try {
    const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'fallback-secret')
    const { payload } = await jwtVerify(token, secret)

    // For auth routes, allow if user is logged in but not fully authenticated
    if (authRoutes.some(route => pathname.startsWith(route))) {
      if (payload.step === 'fully-authenticated') {
        // Already fully authenticated, redirect to dashboard
        return NextResponse.redirect(new URL('/dashboard', request.url))
      }
      
      // Allow access if in 2FA flow
      if (payload.step === 'needs-2fa-setup' || payload.step === 'needs-2fa-verification') {
        return NextResponse.next()
      }
      
      // Invalid state
      return NextResponse.redirect(new URL('/', request.url))
    }

    // For protected routes and APIs, require full authentication
    if (protectedRoutes.some(route => pathname.startsWith(route)) ||
        protectedApiRoutes.some(route => pathname.startsWith(route))) {
      
      if (payload.step !== 'fully-authenticated') {
        // Not fully authenticated
        if (pathname.startsWith('/api/')) {
          return NextResponse.json({ error: 'Authentication not complete' }, { status: 401 })
        }
        return NextResponse.redirect(new URL('/auth/verify-2fa', request.url))
      }
      
      // Additional session validation happens in the API routes themselves
      return NextResponse.next()
    }

    // If user is fully authenticated and trying to access login page, redirect to dashboard
    if (pathname === '/' && payload.step === 'fully-authenticated') {
      return NextResponse.redirect(new URL('/dashboard', request.url))
    }

    // If user is in 2FA flow and trying to access login page, redirect to 2FA
    if (pathname === '/' && (payload.step === 'needs-2fa-setup' || payload.step === 'needs-2fa-verification')) {
      return NextResponse.redirect(new URL('/auth/verify-2fa', request.url))
    }

    return NextResponse.next()
  } catch (error) {
    console.error('Middleware error:', error)
    
    // Invalid token, clear it and redirect appropriately
    const response = pathname.startsWith('/api/') 
      ? NextResponse.json({ error: 'Invalid token' }, { status: 401 })
      : NextResponse.redirect(new URL('/', request.url))
    
    response.cookies.set('auth-token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0
    })
    
    return response
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
