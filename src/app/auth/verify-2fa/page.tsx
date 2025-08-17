'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function Verify2FA() {
  const [token, setToken] = useState('')
  const [qrCode, setQrCode] = useState('')
  const [secret, setSecret] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [isSetup, setIsSetup] = useState(false)
  const router = useRouter()

  useEffect(() => {
    // Check if user needs to set up 2FA or just verify
    checkSetupStatus()
  }, [])

  const checkSetupStatus = async () => {
    try {
      const response = await fetch('/api/auth/check-2fa-setup')
      const data = await response.json()
      
      if (data.needsSetup) {
        setIsSetup(true)
        setQrCode(data.qrCode)
        setSecret(data.secret)
      }
    } catch (error) {
      console.error('Error checking 2FA setup:', error)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    try {
      const response = await fetch('/api/auth/verify-2fa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token }),
      })

      const data = await response.json()

      if (response.ok) {
        // Redirect to dashboard
        router.push('/dashboard')
      } else {
        setError(data.error || '2FA verification failed')
      }
    } catch (error) {
      setError('An error occurred during 2FA verification')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            {isSetup ? 'Set up Two-Factor Authentication' : 'Two-Factor Authentication'}
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            {isSetup 
              ? 'Scan the QR code with your authenticator app' 
              : 'Enter the 6-digit code from your authenticator app'
            }
          </p>
        </div>

        {isSetup && (
          <div className="text-center space-y-4">
            <div className="bg-white p-4 rounded-lg shadow-md">
              {qrCode && (
                <div className="mb-4">
                  <img src={qrCode} alt="QR Code" className="mx-auto" />
                </div>
              )}
              <div className="text-sm text-gray-600">
                <p className="mb-2">Manual entry key:</p>
                <code className="bg-gray-100 p-2 rounded text-xs break-all">
                  {secret}
                </code>
              </div>
            </div>
            <div className="text-sm text-gray-600">
              <p>1. Install an authenticator app (Google Authenticator, Authy, etc.)</p>
              <p>2. Scan the QR code or enter the manual key</p>
              <p>3. Enter the 6-digit code below</p>
            </div>
          </div>
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div>
            <label htmlFor="token" className="block text-sm font-medium text-gray-700 mb-2">
              6-digit verification code
            </label>
            <input
              id="token"
              name="token"
              type="text"
              maxLength={6}
              required
              className="appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm text-center text-lg font-mono"
              placeholder="000000"
              value={token}
              onChange={(e) => setToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
            />
          </div>

          {error && (
            <div className="text-red-600 text-sm text-center">
              {error}
            </div>
          )}

          <div>
            <button
              type="submit"
              disabled={isLoading || token.length !== 6}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Verifying...' : (isSetup ? 'Complete Setup' : 'Verify')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
