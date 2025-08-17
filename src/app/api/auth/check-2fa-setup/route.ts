import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import QRCode from 'qrcode'
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
    
    const sessionId = payload.sessionId as string
    if (!sessionId) {
      return NextResponse.json(
        { error: 'Invalid session' },
        { status: 401 }
      )
    }

    // Check if user needs to set up 2FA
    if (payload.step === 'needs-2fa-setup') {
      // Generate 2FA secret and QR code using secure database function
      const setup = await AuthService.setup2FA(sessionId)
      
      if (!setup) {
        return NextResponse.json(
          { error: 'Failed to generate 2FA setup' },
          { status: 500 }
        )
      }

      // Generate QR code
      const qrCodeUrl = await QRCode.toDataURL(setup.qrCode)

      return NextResponse.json({
        needsSetup: true,
        qrCode: qrCodeUrl,
        secret: setup.secret
      })
    }

    return NextResponse.json({
      needsSetup: false
    })
  } catch (error) {
    console.error('2FA setup check error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
