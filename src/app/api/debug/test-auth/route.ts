import { NextResponse } from 'next/server'
import { supabase } from '@/lib/supabase'

export async function GET() {
  try {
    console.log('🔧 DEBUG: Testing database connection and auth functions')

    // Test 1: Check if the test function exists and works
    const { data: testData, error: testError } = await supabase
      .rpc('test_password_comparison', {
        p_username: 'admin',
        p_password: 'admin123'
      })

    console.log('🔧 DEBUG: Test function result:', testData)
    console.log('🔧 DEBUG: Test function error:', testError)

    // Test 2: Try the actual auth function
    const { data: authData, error: authError } = await supabase
      .rpc('authenticate_user', {
        p_username: 'admin',
        p_password_hash: 'admin123',
        p_ip_address: '127.0.0.1',
        p_user_agent: 'debug-test'
      })

    console.log('🔧 DEBUG: Auth function result:', authData)
    console.log('🔧 DEBUG: Auth function error:', authError)

    // Test 3: Check supabase connection details
    console.log('🔧 DEBUG: Supabase URL:', process.env.NEXT_PUBLIC_SUPABASE_URL)
    console.log('🔧 DEBUG: Anon key exists:', !!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)

    return NextResponse.json({
      success: true,
      tests: {
        passwordTest: {
          data: testData,
          error: testError?.message || null
        },
        authTest: {
          data: authData,
          error: authError?.message || null
        },
        config: {
          supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL,
          hasAnonKey: !!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
          hasJwtSecret: !!process.env.JWT_SECRET
        }
      }
    })

  } catch (error) {
    console.error('💥 DEBUG: Test failed:', error)
    return NextResponse.json({
      success: false,
      error: (error as Error).message
    }, { status: 500 })
  }
}
