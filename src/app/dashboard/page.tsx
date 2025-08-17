'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function Dashboard() {
  const [user, setUser] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [sessionInfo, setSessionInfo] = useState<any>(null)
  const router = useRouter()

  useEffect(() => {
    checkAuthStatus()
  }, [])

  const checkAuthStatus = async () => {
    try {
      const response = await fetch('/api/auth/me')
      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
        setSessionInfo({
          expiresAt: userData.sessionExpiresAt,
          timeRemaining: userData.sessionExpiresAt ? 
            Math.max(0, Math.floor((new Date(userData.sessionExpiresAt).getTime() - Date.now()) / 1000 / 60)) : 0
        })
      } else {
        router.push('/')
      }
    } catch (error) {
      console.error('Auth check failed:', error)
      router.push('/')
    } finally {
      setIsLoading(false)
    }
  }

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      router.push('/')
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-indigo-600"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="bg-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-xl font-bold text-gray-900">Y-Be.tech CRM</h1>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-600">
                <span className="text-gray-700 font-medium">Welcome, {user?.username}</span>
                {sessionInfo && (
                  <div className="text-xs">
                    Session expires in {sessionInfo.timeRemaining} minutes
                  </div>
                )}
              </div>
              <button
                onClick={handleLogout}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="border-4 border-dashed border-gray-200 rounded-lg p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Dashboard</h2>
            
            {/* Dashboard Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className="w-8 h-8 bg-indigo-500 rounded-md flex items-center justify-center">
                        <span className="text-white font-bold">C</span>
                      </div>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Total Customers
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          Coming Soon
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center">
                        <span className="text-white font-bold">W</span>
                      </div>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Workflows
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          n8n Integration
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className="w-8 h-8 bg-blue-500 rounded-md flex items-center justify-center">
                        <span className="text-white font-bold">D</span>
                      </div>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Database
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          Supabase Ready
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-white shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <button className="bg-indigo-50 border border-indigo-200 rounded-lg p-4 text-left hover:bg-indigo-100 transition-colors">
                  <div className="text-indigo-600 font-medium">Add Customer</div>
                  <div className="text-sm text-gray-600 mt-1">Create new customer record</div>
                </button>
                
                <button className="bg-green-50 border border-green-200 rounded-lg p-4 text-left hover:bg-green-100 transition-colors">
                  <div className="text-green-600 font-medium">View Workflows</div>
                  <div className="text-sm text-gray-600 mt-1">Manage n8n workflows</div>
                </button>
                
                <button className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-left hover:bg-blue-100 transition-colors">
                  <div className="text-blue-600 font-medium">Reports</div>
                  <div className="text-sm text-gray-600 mt-1">View analytics and reports</div>
                </button>
                
                <button className="bg-purple-50 border border-purple-200 rounded-lg p-4 text-left hover:bg-purple-100 transition-colors">
                  <div className="text-purple-600 font-medium">Settings</div>
                  <div className="text-sm text-gray-600 mt-1">Configure system settings</div>
                </button>
              </div>
            </div>

            {/* Welcome Message */}
            <div className="mt-8 bg-indigo-50 border border-indigo-200 rounded-lg p-6">
              <h3 className="text-lg font-medium text-indigo-900 mb-2">Welcome to Y-Be.tech CRM</h3>
              <p className="text-indigo-700">
                Your secure internal CRM system is ready. The dashboard will be expanded with customer management, 
                n8n workflow integration, and Supabase data connections as we develop the features.
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
