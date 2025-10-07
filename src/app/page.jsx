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
      const token = await firebaseUser.getIdToken()
      localStorage.setItem('auth-token', token)
      return token
    } catch (error) {
      console.error('Error getting Firebase token:', error)
      throw error
    }
  }

  // Get user role from backend
  const getUserFromBackend = async (email) => {
    try {
      const token = localStorage.getItem('auth-token')
      
      const response = await fetch(`/api/user?email=${encodeURIComponent(email)}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch user data')
      }
      
      if (data.exists && data.user) {
        // Store complete user info in localStorage
        localStorage.setItem('user-info', JSON.stringify(data.user))
        return data.user
      }
      
      throw new Error('User not found in database')
    } catch (error) {
      console.error('Error fetching user from backend:', error)
      throw error
    }
  }

  // Validate POS access
  const validatePOSAccess = async (firebaseUser) => {
    try {
      // Store Firebase token
      await storeFirebaseToken(firebaseUser)

      // Get user data from database
      const dbUser = await getUserFromBackend(firebaseUser.email)

      // Check if user has POS or admin role
      if (dbUser.role !== 'pos' && dbUser.role !== 'admin') {
        await Swal.fire({
          icon: 'error',
          title: 'Access Denied',
          text: 'You do not have permission to access the POS system. Only POS users can login here.',
          confirmButtonColor: '#7c3aed',
        })
        
        localStorage.removeItem('auth-token')
        localStorage.removeItem('user-info')
        return null
      }

      // Check if user has been assigned a branch
      if (!dbUser.branch) {
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

      return dbUser
    } catch (error) {
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
      } else {
        // Not authorized, show message and logout
        Swal.fire({
          icon: 'error',
          title: 'Access Denied',
          text: 'You do not have permission to access the POS system. Please contact an administrator.',
          confirmButtonColor: '#7c3aed',
        }).then(() => {
          localStorage.removeItem('auth-token')
          localStorage.removeItem('user-info')
          router.push('/')
        })
      }
    }
  }, [user, router])

  // Google login function
  const handleGoogleLoginAndRedirect = async () => {
    setIsLoading(true)
    try {
      const result = await handleGoogleSignIn()
      if (result.user) {
        const dbUser = await validatePOSAccess(result.user)
        
        if (dbUser) {
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: `Welcome, ${dbUser.name}!`,
            text: `Branch: ${dbUser.branch.charAt(0).toUpperCase() + dbUser.branch.slice(1)}`,
            showConfirmButton: false,
            timer: 3000,
            timerProgressBar: true,
          })
          router.push('/pos')
        }
      }
    } catch (error) {
      console.error('Google Sign-In Error:', error)
      Swal.fire({
        icon: 'error',
        title: 'Login Failed',
        text: 'Google Sign-In failed. Please try again.',
        confirmButtonColor: '#7c3aed',
      })
    } finally {
      setIsLoading(false)
    }
  }

  // Apple login function
  const handleAppleLoginAndRedirect = async () => {
    setIsLoading(true)
    try {
      const result = await handleAppleSignIn()
      if (result.user) {
        const dbUser = await validatePOSAccess(result.user)
        
        if (dbUser) {
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: `Welcome, ${dbUser.name}!`,
            text: `Branch: ${dbUser.branch.charAt(0).toUpperCase() + dbUser.branch.slice(1)}`,
            showConfirmButton: false,
            timer: 3000,
            timerProgressBar: true,
          })
          router.push('/pos')
        }
      }
    } catch (error) {
      console.error('Apple Sign-In Error:', error)
      Swal.fire({
        icon: 'error',
        title: 'Login Failed',
        text: 'Apple Sign-In failed. Please try again.',
        confirmButtonColor: '#7c3aed',
      })
    } finally {
      setIsLoading(false)
    }
  }

  // Form Submit For Login
  const onSubmit = async (data) => {
    setIsLoading(true)

    try {
      // Sign in with Firebase
      const result = await signIn(data.email, data.password)

      if (!result.user.emailVerified) {
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
        // Success - redirect to POS
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: `Welcome, ${dbUser.name}!`,
          text: `Branch: ${dbUser.branch.charAt(0).toUpperCase() + dbUser.branch.slice(1)}`,
          showConfirmButton: false,
          timer: 3000,
          timerProgressBar: true,
        })

        router.push('/pos')
      }
    } catch (error) {
      console.error('Login error:', error)

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
      <div className="w-full max-w-md p-8">
        <div className="bg-white rounded-2xl shadow-xl p-8 space-y-6">
          {/* Logo and Title */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <div className="bg-purple-100 p-4 rounded-full">
                <Store size={48} className="text-purple-600" />
              </div>
            </div>
            <h1 className="text-3xl font-bold text-gray-900">VWV POS System</h1>
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
                href="/"
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
