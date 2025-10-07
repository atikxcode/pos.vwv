// src/app/pos/page.jsx
'use client'

import { useState, useEffect, useContext } from 'react'
import { useForm } from 'react-hook-form'
import { AuthContext } from '../../../Provider/AuthProvider'
import { useRouter } from 'next/navigation'
import Swal from 'sweetalert2'
import { Store, Search, Trash2, Plus, Minus, ShoppingCart, LogOut, CreditCard } from 'lucide-react'

export default function POSPage() {
  const { user, logOut } = useContext(AuthContext)
  const router = useRouter()
  
  const [loading, setLoading] = useState(true)
  const [userInfo, setUserInfo] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [products, setProducts] = useState([])
  const [cartItems, setCartItems] = useState([])
  const [discount, setDiscount] = useState(0)
  const [paymentMethod, setPaymentMethod] = useState('cash')

  // React Hook Form
  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm()

  // Get POS user's branch from database
  useEffect(() => {
    const fetchUserDetails = async () => {
      if (!user?.email) {
        console.log('No user email found')
        return
      }

      try {
        console.log('Fetching user details for:', user.email)
        const token = localStorage.getItem('auth-token')
        const response = await fetch(`/api/user?email=${encodeURIComponent(user.email)}`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })

        if (response.status === 401) {
          console.log('Token expired, redirecting to login')
          localStorage.removeItem('auth-token')
          localStorage.removeItem('user-info')
          router.push('/')
          return
        }

        if (response.ok) {
          const data = await response.json()
          if (data.user) {
            const userDetails = {
              ...data.user,
              branch: data.user.branch?.toLowerCase()
            }
            setUserInfo(userDetails)
            localStorage.setItem('user-info', JSON.stringify(userDetails))
            console.log('POS User Details Loaded:', {
              email: data.user.email,
              role: data.user.role,
              branch: data.user.branch
            })
          }
        } else {
          console.error('Failed to fetch user details:', response.status)
          Swal.fire({
            icon: 'error',
            title: 'Access Denied',
            text: 'Could not load user details',
            confirmButtonColor: '#7c3aed',
          }).then(() => {
            router.push('/')
          })
        }
      } catch (error) {
        console.error('Error fetching user details:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchUserDetails()
  }, [user, router])

  // Check authentication
  useEffect(() => {
    if (!user) {
      router.push('/')
      return
    }
    
    const storedUserInfo = JSON.parse(localStorage.getItem('user-info') || '{}')
    
    if (storedUserInfo.role !== 'pos' && storedUserInfo.role !== 'admin') {
      Swal.fire({
        icon: 'error',
        title: 'Access Denied',
        text: 'POS role required',
        confirmButtonColor: '#7c3aed',
      }).then(() => {
        router.push('/')
      })
      return
    }
  }, [user, router])

  // Search products by branch
  const handleSearch = async (query) => {
    if (!query.trim() || !userInfo?.branch) {
      setProducts([])
      return
    }

    try {
      const token = localStorage.getItem('auth-token')
      const response = await fetch(
        `/api/products?search=${encodeURIComponent(query)}&branch=${userInfo.branch}&status=active`, 
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      )
      
      if (response.ok) {
        const data = await response.json()
        console.log('Products fetched:', data.products?.length || 0)
        setProducts(data.products || [])
      } else {
        console.error('Failed to fetch products:', response.status)
        setProducts([])
      }
    } catch (error) {
      console.error('Error searching products:', error)
      setProducts([])
    }
  }

  // Add to cart
  const addToCart = (product) => {
    const stockKey = `${userInfo.branch}_stock`
    const availableStock = product.stock?.[stockKey] || 0
    
    if (availableStock <= 0) {
      Swal.fire({
        icon: 'error',
        title: 'Out of Stock',
        text: 'This product is out of stock in your branch',
        confirmButtonColor: '#7c3aed',
        timer: 2000
      })
      return
    }

    const existingItem = cartItems.find(item => item._id === product._id)
    
    if (existingItem) {
      const newQuantity = existingItem.quantity + 1
      if (newQuantity > availableStock) {
        Swal.fire({
          icon: 'warning',
          title: 'Stock Limit',
          text: `Only ${availableStock} items available`,
          confirmButtonColor: '#7c3aed',
          timer: 2000
        })
        return
      }
      
      setCartItems(cartItems.map(item =>
        item._id === product._id
          ? { ...item, quantity: newQuantity }
          : item
      ))
    } else {
      setCartItems([...cartItems, { ...product, quantity: 1 }])
    }
    
    setSearchQuery('')
    setProducts([])
  }

  // Update quantity
  const updateQuantity = (productId, newQuantity) => {
    if (newQuantity <= 0) {
      removeFromCart(productId)
      return
    }

    const item = cartItems.find(i => i._id === productId)
    if (item) {
      const stockKey = `${userInfo.branch}_stock`
      const availableStock = item.stock?.[stockKey] || 0
      
      if (newQuantity > availableStock) {
        Swal.fire({
          icon: 'warning',
          title: 'Stock Limit',
          text: `Only ${availableStock} items available`,
          confirmButtonColor: '#7c3aed',
          timer: 2000
        })
        return
      }
    }
    
    setCartItems(cartItems.map(item =>
      item._id === productId ? { ...item, quantity: newQuantity } : item
    ))
  }

  // Remove from cart
  const removeFromCart = (productId) => {
    setCartItems(cartItems.filter(item => item._id !== productId))
  }

  // Calculate total quantity
  const calculateTotalQuantity = () => {
    return cartItems.reduce((sum, item) => sum + item.quantity, 0)
  }

  // Calculate values
  const calculateSubtotal = () => {
    return cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0)
  }

  const calculateVAT = () => {
    return calculateSubtotal() * 0.15 // 15% VAT (Adjusted - not added to total)
  }

  const calculateGrandTotal = () => {
    return calculateSubtotal() // VAT is adjusted, not added
  }

  const calculateAdjustedAmount = () => {
    return calculateGrandTotal() - discount
  }

  // Complete sale - FULL BACKEND INTEGRATION
  const onSubmit = async (data) => {
    if (cartItems.length === 0) {
      Swal.fire({
        icon: 'warning',
        title: 'Empty Cart',
        text: 'Please add items to cart',
        confirmButtonColor: '#7c3aed',
      })
      return
    }

    if (!userInfo?.branch) {
      Swal.fire({
        icon: 'error',
        title: 'Branch Error',
        text: 'User branch not found',
        confirmButtonColor: '#7c3aed',
      })
      return
    }

    try {
      setLoading(true)

      const totalAmount = calculateGrandTotal()
      const adjustedAmount = calculateAdjustedAmount()

      // Prepare sale data matching backend expectations
      const saleData = {
        phone: data.phone, // Mandatory phone number
        items: cartItems.map(item => ({
          productId: item._id,
          productName: item.name,
          productCode: item.productCode || '',
          branch: userInfo.branch.toLowerCase(),
          quantity: item.quantity,
          unitPrice: item.price,
          totalPrice: item.price * item.quantity
        })),
        totalAmount: totalAmount,
        discount: discount,
        adjustedAmount: adjustedAmount,
        paymentMethod: paymentMethod, // Single payment method
        payment: {
          methods: [{
            id: paymentMethod,
            name: paymentMethod.charAt(0).toUpperCase() + paymentMethod.slice(1),
            type: paymentMethod === 'cash' ? 'cash' : 
                  ['bkash', 'nagad', 'rocket'].includes(paymentMethod) ? 'mobile_banking' : 'card',
            amount: adjustedAmount
          }],
          totalAmount: totalAmount,
          totalPaid: adjustedAmount,
          change: 0
        },
        customer: {
          name: 'Walk-in Customer',
          phone: data.phone
        },
        paymentType: paymentMethod === 'cash' ? 'cash' : 
                     ['bkash', 'nagad', 'rocket'].includes(paymentMethod) ? 'mobile_banking' : 'card',
        status: 'completed',
        cashier: userInfo.name || 'POS User'
      }

      console.log('POS Sale Data:', JSON.stringify(saleData, null, 2))

      const token = localStorage.getItem('auth-token')
      const response = await fetch('/api/sales', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(saleData)
      })

      if (response.status === 401) {
        console.log('Token expired')
        localStorage.removeItem('auth-token')
        localStorage.removeItem('user-info')
        router.push('/')
        return
      }

      if (response.ok) {
        const result = await response.json()
        console.log('Sale saved successfully:', result)

        Swal.fire({
          icon: 'success',
          title: 'Sale Completed!',
          html: `
            <div class="text-left">
              <p><strong>Sale ID:</strong> ${result.saleId || 'N/A'}</p>
              <p><strong>Phone:</strong> ${data.phone}</p>
              <p><strong>Payment:</strong> ${paymentMethod.toUpperCase()}</p>
              <p><strong>Items:</strong> ${calculateTotalQuantity()}</p>
              <p><strong>Total:</strong> ৳${adjustedAmount.toFixed(2)}</p>
            </div>
          `,
          confirmButtonColor: '#7c3aed',
        })

        // Clear cart and form
        setCartItems([])
        setDiscount(0)
        setPaymentMethod('cash')
        reset()
      } else {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Failed to process sale')
      }
    } catch (error) {
      console.error('POS Sale Error:', error)
      Swal.fire({
        icon: 'error',
        title: 'Sale Failed',
        text: error.message || 'Failed to complete sale',
        confirmButtonColor: '#7c3aed',
      })
    } finally {
      setLoading(false)
    }
  }

  // Clear cart
  const clearCart = () => {
    if (cartItems.length === 0) return
    
    Swal.fire({
      title: 'Clear Cart?',
      text: 'This will remove all items',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#7c3aed',
      cancelButtonColor: '#6b7280',
      confirmButtonText: 'Yes, clear it'
    }).then((result) => {
      if (result.isConfirmed) {
        setCartItems([])
        setDiscount(0)
        reset()
      }
    })
  }

  // Logout
  const handleLogout = async () => {
    const result = await Swal.fire({
      title: 'Logout?',
      icon: 'question',
      showCancelButton: true,
      confirmButtonColor: '#7c3aed',
      cancelButtonColor: '#6b7280',
      confirmButtonText: 'Yes, logout'
    })

    if (result.isConfirmed) {
      await logOut()
      localStorage.removeItem('auth-token')
      localStorage.removeItem('user-info')
      router.push('/')
    }
  }

  // Loading state
  if (loading || !userInfo?.branch) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading POS System...</p>
          <p className="text-sm text-gray-500 mt-2">Getting your branch information...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-indigo-100">
      {/* Header */}
      <div className="bg-purple-600 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <Store size={32} />
            <div>
              <h1 className="text-xl font-bold">VWV POS</h1>
              <p className="text-sm opacity-90">
                {userInfo?.name} • {userInfo?.branch?.toUpperCase()} Branch
              </p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 rounded-lg transition-colors"
          >
            <LogOut size={18} />
            Logout
          </button>
        </div>
      </div>

      <div className="p-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* LEFT: Search & Products */}
          <div className="lg:col-span-2">
            {/* Search Bar */}
            <div className="bg-white rounded-lg shadow-lg p-4 mb-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={20} />
                <input
                  type="text"
                  placeholder="Search by product name or barcode..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value)
                    handleSearch(e.target.value)
                  }}
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 text-lg"
                  autoFocus
                />
              </div>

              {/* Search Results Dropdown */}
              {products.length > 0 && (
                <div className="mt-2 max-h-96 overflow-y-auto border border-gray-200 rounded-lg">
                  {products.map((product) => (
                    <div
                      key={product._id}
                      onClick={() => addToCart(product)}
                      className="p-4 hover:bg-purple-50 cursor-pointer border-b last:border-b-0 transition-colors"
                    >
                      <div className="flex justify-between items-center">
                        <div>
                          <h3 className="font-semibold text-gray-900">{product.name}</h3>
                          <p className="text-sm text-gray-500">{product.productCode}</p>
                        </div>
                        <div className="text-right">
                          <p className="text-xl font-bold text-purple-600">৳{product.price}</p>
                          <p className="text-xs text-gray-500">
                            Stock: {product.stock?.[`${userInfo?.branch}_stock`] || 0}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Cart Items Display */}
            <div className="bg-white rounded-lg shadow-lg p-4 flex flex-col h-[calc(100vh-280px)]">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-bold text-gray-900">Added Items</h2>
                {cartItems.length > 0 && (
                  <button
                    onClick={clearCart}
                    className="text-red-500 hover:text-red-700 text-sm font-semibold"
                  >
                    Clear All
                  </button>
                )}
              </div>

              <div className="space-y-2 flex-1 overflow-y-auto">
                {cartItems.length === 0 ? (
                  <div className="text-center py-12 text-gray-500">
                    <ShoppingCart size={64} className="mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No items added yet</p>
                  </div>
                ) : (
                  cartItems.map((item) => (
                    <div key={item._id} className="border border-gray-200 rounded-lg p-3 hover:border-purple-300 transition-colors">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <h3 className="font-semibold text-sm text-gray-900">{item.name}</h3>
                          <p className="text-xs text-gray-500">{item.productCode}</p>
                        </div>
                        <button
                          onClick={() => removeFromCart(item._id)}
                          className="text-red-500 hover:text-red-700"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => updateQuantity(item._id, item.quantity - 1)}
                            className="w-7 h-7 bg-gray-200 rounded hover:bg-gray-300 flex items-center justify-center"
                          >
                            <Minus size={14} />
                          </button>
                          <span className="w-10 text-center font-semibold">{item.quantity}</span>
                          <button
                            onClick={() => updateQuantity(item._id, item.quantity + 1)}
                            className="w-7 h-7 bg-purple-600 text-white rounded hover:bg-purple-700 flex items-center justify-center"
                          >
                            <Plus size={14} />
                          </button>
                        </div>
                        <div className="text-right">
                          <p className="text-xs text-gray-500">৳{item.price} × {item.quantity}</p>
                          <p className="font-bold text-purple-600 text-lg">৳{(item.price * item.quantity).toFixed(2)}</p>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* RIGHT: Cart Summary & Checkout */}
          <div className="lg:col-span-1">
            <form onSubmit={handleSubmit(onSubmit)} className="bg-white rounded-lg shadow-lg p-4">
              <div className="flex items-center gap-2 mb-6">
                <ShoppingCart size={20} className="text-purple-600" />
                <h2 className="text-lg font-bold text-gray-900">Cart ({cartItems.length})</h2>
              </div>

              <div className='flex justify-center text-purple-600 text-lg font-semibold tracking-wider mb-4 pb-3 border-b'>
                Customer Information
              </div>

              {/* Phone Number - Mandatory */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Phone Number <span className="text-red-500">*</span>
                </label>
                <input
                  type="tel"
                  {...register('phone', {
                    required: 'Phone number is required',
                    pattern: {
                      value: /^01[3-9]\d{8}$/,
                      message: 'Invalid Bangladesh phone number'
                    }
                  })}
                  placeholder="01XXXXXXXXX"
                  className={`w-full px-3 py-2 border ${errors.phone ? 'border-red-500' : 'border-gray-300'} rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm`}
                />
                {errors.phone && (
                  <p className="text-red-500 text-xs mt-1">{errors.phone.message}</p>
                )}
              </div>

              {/* Quantity of Items */}
              <div className="mb-4 pb-4 border-b">
                <div className="flex justify-between text-sm font-medium">
                  <span className="text-gray-700">Quantity of Items</span>
                  <span className="text-purple-600 font-bold">{calculateTotalQuantity()}</span>
                </div>
              </div>

              {/* Calculations */}
              <div className="space-y-2 mb-4 pb-4 border-b">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Subtotal</span>
                  <span className="font-semibold">৳{calculateSubtotal().toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">
                    VAT (15%) 
                    <span className="text-xs text-purple-600 ml-1">(Adjusted)</span>
                  </span>
                  <span className="font-semibold text-gray-500">৳{calculateVAT().toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-sm font-bold text-gray-900">
                  <span>Grand Total</span>
                  <span>৳{calculateGrandTotal().toFixed(2)}</span>
                </div>
              </div>

              {/* Discount - Integer Only */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Discount (৳)
                </label>
                <input
                  type="number"
                  min="0"
                  max={calculateGrandTotal()}
                  step="1"
                  value={discount === 0 ? '' : discount}
                  onChange={(e) => setDiscount(parseInt(e.target.value) || 0)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                  placeholder="0"
                />
              </div>

              {/* Payment Method */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  <CreditCard size={16} className="inline mr-1" />
                  Payment Method
                </label>
                <select
                  value={paymentMethod}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
                >
                  <option value="cash">Cash</option>
                  <option value="bkash">bKash</option>
                  <option value="nagad">Nagad</option>
                  <option value="rocket">Rocket</option>
                  <option value="credit_card">Credit Card</option>
                  <option value="debit_card">Debit Card</option>
                  <option value="american_express">American Express</option>
                </select>
              </div>

              {/* Adjusted Amount - Before Complete Sale Button */}
              <div className="mb-4 p-4 bg-gradient-to-r from-purple-50 to-blue-50 rounded-lg border-2 border-purple-200">
                <div className="flex justify-between items-center">
                  <span className="text-base font-bold text-gray-900">Adjusted Amount</span>
                  <span className="text-2xl font-bold text-purple-600">৳{calculateAdjustedAmount().toFixed(2)}</span>
                </div>
              </div>

              {/* Complete Sale Button */}
              <button
                type="submit"
                disabled={cartItems.length === 0 || loading}
                className="w-full py-3 bg-purple-600 text-white font-bold rounded-lg hover:bg-purple-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? 'Processing...' : 'Complete Sale'}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  )
}
