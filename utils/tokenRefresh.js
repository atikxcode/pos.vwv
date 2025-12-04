// utils/tokenRefresh.js
import { getAuth } from 'firebase/auth'

// Refresh interval: 50 minutes (before the 1-hour expiration)
const REFRESH_INTERVAL = 50 * 60 * 1000 // 50 minutes in milliseconds

let refreshTimerId = null

/**
 * Start automatic token refresh
 * This will refresh the Firebase token every 50 minutes to keep the session alive
 */
export const startTokenRefresh = () => {
    // Clear any existing refresh timer
    stopTokenRefresh()

    console.log('🔄 Starting automatic token refresh (every 50 minutes)')

    // Set up interval to refresh token every 50 minutes
    refreshTimerId = setInterval(async () => {
        try {
            const auth = getAuth()
            const user = auth.currentUser

            if (user) {
                console.log('🔄 Refreshing Firebase token...')

                // Force refresh the token
                const newToken = await user.getIdToken(true)

                // Update localStorage with new token
                localStorage.setItem('auth-token', newToken)

                console.log('✅ Token refreshed successfully')
                console.log('⏰ Next refresh in 50 minutes')
            } else {
                console.log('⚠️ No user logged in, stopping token refresh')
                stopTokenRefresh()
            }
        } catch (error) {
            console.error('❌ Error refreshing token:', error)

            // If refresh fails, user might need to log in again
            if (error.code === 'auth/user-token-expired' || error.code === 'auth/network-request-failed') {
                console.error('⚠️ Token refresh failed - user may need to log in again')
                stopTokenRefresh()
            }
        }
    }, REFRESH_INTERVAL)

    // Also refresh immediately to ensure we have a fresh token
    setTimeout(async () => {
        try {
            const auth = getAuth()
            const user = auth.currentUser
            if (user) {
                console.log('🔄 Initial token refresh...')
                const newToken = await user.getIdToken(true)
                localStorage.setItem('auth-token', newToken)
                console.log('✅ Initial token refreshed')
            }
        } catch (error) {
            console.error('❌ Initial token refresh failed:', error)
        }
    }, 1000) // Refresh after 1 second of starting
}

/**
 * Stop automatic token refresh
 * Call this when user logs out
 */
export const stopTokenRefresh = () => {
    if (refreshTimerId) {
        clearInterval(refreshTimerId)
        refreshTimerId = null
        console.log('⏹️ Token refresh stopped')
    }
}

/**
 * Manually refresh token
 * Useful for refreshing token on-demand
 */
export const refreshTokenNow = async () => {
    try {
        const auth = getAuth()
        const user = auth.currentUser

        if (!user) {
            throw new Error('No user logged in')
        }

        console.log('🔄 Manual token refresh...')
        const newToken = await user.getIdToken(true)
        localStorage.setItem('auth-token', newToken)
        console.log('✅ Token manually refreshed')

        return newToken
    } catch (error) {
        console.error('❌ Manual token refresh failed:', error)
        throw error
    }
}
