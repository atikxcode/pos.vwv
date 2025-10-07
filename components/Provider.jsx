'use client'

import AuthProvider from '../Provider/AuthProvider'

export default function Providers({ children }) {
  return (
    <AuthProvider>
          {children}
    </AuthProvider>
  )
}
