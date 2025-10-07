'use client'

import { useForm } from 'react-hook-form'
import { useContext, useEffect, useState } from 'react'
import { HiEye, HiEyeOff } from 'react-icons/hi'
import Image from 'next/image'
import { AuthContext } from '../../Provider/AuthProvider'
import { useRouter } from 'next/navigation'
import Swal from 'sweetalert2'
import { Store, ShieldCheck } from 'lucide-react'

export default function POSLoginPage() {
  const { user, signIn, handleGoogleSignIn, handleAppleSignIn } = useContext(AuthContext)
  const router = useRouter()

  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  // Hook Form
  const {
    register,
    handleSubmit,
    formState: { errors, isValid },
  } = useForm({ mode: 'onChange' })

  // Function to get Firebase token and store it
  const storeFirebaseToken = async (firebaseUser) => {
    try {
      console.log('🔍 Getting Firebase token for:', firebaseUser.email)
      const token = await firebaseUser.getIdToken(true) // Force refresh token
      localStorage.setItem('auth-token', token)
      console.log('✅ Token stored successfully')
      return token
    } catch (error) {
      console.error('❌ Error getting Firebase token:', error)
      throw error
    }
  }

  // Get user role from backend with retry logic
  const getUserFromBackend = async (email, retryCount = 0) => {
    const MAX_RETRIES = 3
    
    try {
      const token = localStorage.getItem('auth-token')
      console.log(`🔍 Fetching user from backend (attempt ${retryCount + 1}):`, { email, hasToken: !!token })
      
      if (!token) {
        throw new Error('No authentication token found')
      }
      
      const response = await fetch(`/api/user?email=${encodeURIComponent(email)}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
      })

      console.log('🔍 Backend response status:', response.status)

      const data = await response.json()
      console.log('🔍 Backend response:', { 
        exists: data.exists, 
        role: data.user?.role, 
        branch: data.user?.branch 
      })
      
      if (!response.ok) {
        console.error('❌ Backend error:', data.error)
        
        // Retry on certain errors
        if (retryCount < MAX_RETRIES && (response.status === 401 || response.status === 500)) {
          console.log(`🔄 Retrying... (${retryCount + 1}/${MAX_RETRIES})`)
          await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1))) // Exponential backoff
          return getUserFromBackend(email, retryCount + 1)
        }
        
        throw new Error(data.error || 'Failed to fetch user data')
      }
      
      if (data.exists && data.user) {
        // Store complete user info in localStorage
        localStorage.setItem('user-info', JSON.stringify(data.user))
        console.log('✅ User info stored in localStorage')
        return data.user
      }
      
      throw new Error('User not found in database')
    } catch (error) {
      console.error('❌ Error fetching user from backend:', error)
      
      // Retry on network errors
      if (retryCount < MAX_RETRIES && error.message.includes('fetch')) {
        console.log(`🔄 Retrying due to network error... (${retryCount + 1}/${MAX_RETRIES})`)
        await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1)))
        return getUserFromBackend(email, retryCount + 1)
      }
      
      throw error
    }
  }

  // Validate POS access with retry and delay
  const validatePOSAccess = async (firebaseUser) => {
    const startTime = Date.now()
    const MIN_WAIT_TIME = 5000 // 5 seconds minimum wait
    
    try {
      console.log('🔍 Starting POS access validation for:', firebaseUser.email)
      
      // Step 1: Store Firebase token
      await storeFirebaseToken(firebaseUser)
      
      // Step 2: Small delay to ensure token is persisted
      await new Promise(resolve => setTimeout(resolve, 200))

      // Step 3: Get user data from database with retry
      const dbUser = await getUserFromBackend(firebaseUser.email)

      // Step 4: Check if user has POS or admin role
      if (dbUser.role !== 'pos' && dbUser.role !== 'admin') {
        console.log('❌ Access denied: Role is', dbUser.role)
        
        // Wait remaining time before showing error
        const elapsed = Date.now() - startTime
        if (elapsed < MIN_WAIT_TIME) {
          await new Promise(resolve => setTimeout(resolve, MIN_WAIT_TIME - elapsed))
        }
        
        await Swal.fire({
          icon: 'error',
          title: 'Access Denied',
          text: `You do not have permission to access the POS system. Your role is: ${dbUser.role}`,
          confirmButtonColor: '#7c3aed',
        })
        
        localStorage.removeItem('auth-token')
        localStorage.removeItem('user-info')
        return null
      }

      // Step 5: Check if user has been assigned a branch
      if (!dbUser.branch) {
        console.log('❌ No branch assigned')
        
        // Wait remaining time before showing error
        const elapsed = Date.now() - startTime
        if (elapsed < MIN_WAIT_TIME) {
          await new Promise(resolve => setTimeout(resolve, MIN_WAIT_TIME - elapsed))
        }
        
        await Swal.fire({
          icon: 'warning',
          title: 'No Branch Assigned',
          text: 'Your account has not been assigned to a branch yet. Please contact an administrator.',
          confirmButtonColor: '#7c3aed',
        })
        
        localStorage.removeItem('auth-token')
        localStorage.removeItem('user-info')
        return null
      }

      console.log('✅ POS access validated successfully:', { 
        role: dbUser.role, 
        branch: dbUser.branch 
      })
      return dbUser
    } catch (error) {
      console.error('❌ Error in validatePOSAccess:', error)
      
      // Wait remaining time before showing error
      const elapsed = Date.now() - startTime
      if (elapsed < MIN_WAIT_TIME) {
        console.log(`⏳ Waiting ${MIN_WAIT_TIME - elapsed}ms before showing error...`)
        await new Promise(resolve => setTimeout(resolve, MIN_WAIT_TIME - elapsed))
      }
      
      throw error
    }
  }

  // Check if already logged in
  useEffect(() => {
    if (user) {
      const userInfo = JSON.parse(localStorage.getItem('user-info') || '{}')
      
      // Check if user has POS or admin role
      if (userInfo.role === 'pos' || userInfo.role === 'admin') {
        router.push('/pos')
      }
    }
  }, [user, router])

  // Google login function with silent error handling
  const handleGoogleLoginAndRedirect = async () => {
    setIsLoading(true)
    try {
      console.log('🔍 Starting Google Sign-In...')
      const result = await handleGoogleSignIn()
      
      if (result.user) {
        console.log('✅ Google Sign-In successful:', result.user.email)
        const dbUser = await validatePOSAccess(result.user)
        
        if (dbUser) {
          console.log('✅ Redirecting to POS...')
          
          // Show success toast
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: `Welcome, ${dbUser.name}!`,
            text: `Branch: ${dbUser.branch.charAt(0).toUpperCase() + dbUser.branch.slice(1)}`,
            showConfirmButton: false,
            timer: 2000,
            timerProgressBar: true,
          })
          
          // Small delay before redirect
          await new Promise(resolve => setTimeout(resolve, 100))
          router.push('/pos')
        } else {
          // User validation returned null (already showed error in validatePOSAccess)
          console.log('❌ POS validation failed')
        }
      }
    } catch (error) {
      console.error('❌ Google Sign-In Error:', error)
      
      // Only show error if it's not a validation error (those are already handled)
      if (!error.message.includes('permission') && !error.message.includes('branch')) {
        Swal.fire({
          icon: 'error',
          title: 'Login Failed',
          text: error.message || 'Google Sign-In failed. Please try again.',
          confirmButtonColor: '#7c3aed',
        })
      }
    } finally {
      setIsLoading(false)
    }
  }

  // Apple login function with silent error handling
  const handleAppleLoginAndRedirect = async () => {
    setIsLoading(true)
    try {
      console.log('🔍 Starting Apple Sign-In...')
      const result = await handleAppleSignIn()
      
      if (result.user) {
        console.log('✅ Apple Sign-In successful:', result.user.email)
        const dbUser = await validatePOSAccess(result.user)
        
        if (dbUser) {
          console.log('✅ Redirecting to POS...')
          
          // Show success toast
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: `Welcome, ${dbUser.name}!`,
            text: `Branch: ${dbUser.branch.charAt(0).toUpperCase() + dbUser.branch.slice(1)}`,
            showConfirmButton: false,
            timer: 2000,
            timerProgressBar: true,
          })
          
          // Small delay before redirect
          await new Promise(resolve => setTimeout(resolve, 100))
          router.push('/pos')
        } else {
          // User validation returned null (already showed error in validatePOSAccess)
          console.log('❌ POS validation failed')
        }
      }
    } catch (error) {
      console.error('❌ Apple Sign-In Error:', error)
      
      // Only show error if it's not a validation error (those are already handled)
      if (!error.message.includes('permission') && !error.message.includes('branch')) {
        Swal.fire({
          icon: 'error',
          title: 'Login Failed',
          text: error.message || 'Apple Sign-In failed. Please try again.',
          confirmButtonColor: '#7c3aed',
        })
      }
    } finally {
      setIsLoading(false)
    }
  }

  // Form Submit For Login with silent error handling
  const onSubmit = async (data) => {
    setIsLoading(true)

    try {
      console.log('🔍 Starting email/password login...')
      
      // Sign in with Firebase
      const result = await signIn(data.email, data.password)
      console.log('✅ Firebase sign-in successful:', result.user.email)

      if (!result.user.emailVerified) {
        console.log('❌ Email not verified')
        await Swal.fire({
          icon: 'warning',
          title: 'Email Not Verified',
          text: 'Please verify your email before logging in!',
          confirmButtonColor: '#7c3aed',
        })
        setIsLoading(false)
        return
      }

      const dbUser = await validatePOSAccess(result.user)

      if (dbUser) {
        console.log('✅ Redirecting to POS...')
        
        // Show success toast
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: `Welcome, ${dbUser.name}!`,
          text: `Branch: ${dbUser.branch.charAt(0).toUpperCase() + dbUser.branch.slice(1)}`,
          showConfirmButton: false,
          timer: 2000,
          timerProgressBar: true,
        })

        // Small delay before redirect
        await new Promise(resolve => setTimeout(resolve, 100))
        router.push('/pos')
      } else {
        // User validation returned null (already showed error in validatePOSAccess)
        console.log('❌ POS validation failed')
      }
    } catch (error) {
      console.error('❌ Login error:', error)

      // Only show error if it's not a validation error
      if (error.message && (error.message.includes('permission') || error.message.includes('branch'))) {
        // Already handled in validatePOSAccess
        setIsLoading(false)
        return
      }

      let message = 'Login failed'
      if (
        error.code === 'auth/invalid-credential' ||
        error.code === 'auth/wrong-password' ||
        error.code === 'auth/user-not-found' ||
        error.code === 'auth/invalid-email'
      ) {
        message = 'Wrong email or password'
      } else if (error.code === 'auth/too-many-requests') {
        message = 'Too many failed attempts. Please try again later.'
      } else if (error.message && error.message.includes('User not found in database')) {
        message = 'Account not found. Please contact an administrator.'
      } else if (error.message) {
        message = error.message
      }

      Swal.fire({
        icon: 'error',
        title: 'Login Failed',
        text: message,
        confirmButtonColor: '#7c3aed',
      })
    }

    setIsLoading(false)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-50 via-blue-50 to-indigo-100">
      <div className="w-[70%] max-w-2xl p-8">
        <div className="bg-white rounded-2xl shadow-xl p-8 space-y-6">
          {/* Logo and Title */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <img className='h-[150px] w-auto' src="/SocialMediaLogo/company_logo.jpg" alt="VWV Logo" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900">VWV POS SYSTEM</h1>
            <p className="text-gray-600 flex items-center justify-center gap-2">
              <ShieldCheck size={18} className="text-purple-600" />
              Point of Sale Login
            </p>
          </div>

          {/* Info Banner */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
            <p className="text-sm text-purple-800 text-center">
              <strong>POS Access Only</strong>
              <br />
              Only authorized POS users can access this system
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            {/* Email Field */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Email Address
              </label>
              <input
                type="email"
                placeholder="Enter your email"
                {...register('email', { 
                  required: 'Email is required',
                  pattern: {
                    value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                    message: 'Invalid email address'
                  }
                })}
                className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                disabled={isLoading}
              />
              {errors.email && (
                <p className="text-red-500 text-sm mt-1 flex items-center gap-1">
                  {errors.email.message}
                </p>
              )}
            </div>

            {/* Password Field */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your password"
                  {...register('password', {
                    required: 'Password is required',
                  })}
                  className="w-full border border-gray-300 rounded-lg px-4 py-3 pr-12 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute top-1/2 -translate-y-1/2 right-4 text-gray-500 hover:text-gray-700"
                  disabled={isLoading}
                >
                  {showPassword ? (
                    <HiEyeOff size={22} />
                  ) : (
                    <HiEye size={22} />
                  )}
                </button>
              </div>
              {errors.password && (
                <p className="text-red-500 text-sm mt-1 flex items-center gap-1">
                  {errors.password.message}
                </p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={!isValid || isLoading}
              className={`w-full py-3 rounded-lg font-semibold transition-all flex items-center justify-center ${
                isValid && !isLoading
                  ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-lg hover:shadow-xl'
                  : 'bg-gray-200 text-gray-500 cursor-not-allowed'
              }`}
            >
              {isLoading ? (
                <div className="flex items-center">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                  Logging in...
                </div>
              ) : (
                <>
                  <Store size={20} className="mr-2" />
                  Login to POS
                </>
              )}
            </button>
          </form>

          {/* Social Login */}
          <>
            <div className="text-center text-gray-500 text-sm">
              or continue with
            </div>
            <div className="flex justify-center space-x-4">
              {/* Google */}
              <button
                onClick={handleGoogleLoginAndRedirect}
                disabled={isLoading}
                className="w-12 h-12 bg-white border border-gray-300 rounded-full flex items-center justify-center hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-md"
              >
                <Image
                  src="/SocialMediaLogo/Google.png"
                  alt="Google"
                  width={30}
                  height={30}
                />
              </button>

              {/* Apple */}
              <button
                onClick={handleAppleLoginAndRedirect}
                disabled={isLoading}
                className="w-12 h-12 bg-white border border-gray-300 rounded-full flex items-center justify-center hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-md"
              >
                <Image
                  src="/SocialMediaLogo/Apple.png"
                  alt="Apple"
                  width={23}
                  height={23}
                />
              </button>
            </div>
          </>

          {/* Footer Links */}
          <div className="pt-4 border-t border-gray-200 space-y-3">
            <p className="text-center text-sm text-gray-600">
              Don't have POS access?{' '}
              <a
                target='_blank'
                href="https://vwv-bd.vercel.app/"
                className="text-purple-600 hover:text-purple-700 font-medium hover:underline"
              >
                Go to Main Site
              </a>
            </p>
            <p className="text-center text-xs text-gray-500">
              Contact your administrator to request POS access
            </p>
          </div>
        </div>

        {/* Version Info */}
        <div className="text-center mt-6 text-sm text-gray-500">
          VWV POS System v1.0
        </div>
      </div>
    </div>
  )
}
