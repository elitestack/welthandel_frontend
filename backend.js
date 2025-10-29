import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import { google } from 'googleapis';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import emailService from './emailService.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Security Middleware
app.use(helmet());
app.use(cookieParser());

const allowedOrigins = [
  'http://localhost:3000',
  'https://procoin.vercel.app',
  'http://192.168.32.20:3000'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  exposedHeaders: ['X-User-Email']
};

app.use(cors(corsOptions));
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// MongoDB Connection
const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error('MONGODB_URI environment variable is not defined');
}

mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected successfully 🚀'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Admin Schema
const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'superadmin'], default: 'admin' },
  permissions: {
    manageUsers: { type: Boolean, default: true },
    manageDeposits: { type: Boolean, default: true },
    manageWithdrawals: { type: Boolean, default: true },
    sendNotifications: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now },
  refreshTokens: [String]
});

AdminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  } catch (error) {
    next(error);
  }
});

AdminSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const Admin = mongoose.model('Admin', AdminSchema);

// User Schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, required: true },
  currency: { type: String, required: true, default: 'USD' },
  country: { type: String, required: true },
  kycAmount: { type: String, required: true, default: 'pending admin'},
  kycStatus: { type: String, required: true, default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  refreshTokens: [String]
});

// Deposit Schema
const DepositSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: { type: String, required: true },
  currency: { type: String, required: true },
  cryptoAmount: { type: String },
  cryptoCurrency: { type: String },
  walletAddress: { type: String },
  transactionHash: { type: String },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  depositMethod: { type: String },
  bonusApplied: { type: String, default: '0' },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

// User Wallet Schema (All balances as strings)
const UserWalletSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  totalBalance: { type: String, default: '0' },
  availableBalance: { type: String, default: '0' },
  totalProfit: { type: String, default: '0' },
  totalDeposits: { type: String, default: '0' },
  totalWithdrawals: { type: String, default: '0' },
  bonuses: {
    welcomeBonus: {
      amount: { type: String, default: '0' },
      claimed: { type: Boolean, default: false },
      claimDate: Date
    },
    referralBonus: {
      amount: { type: String, default: '0' },
      referrals: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        amount: String,
        date: { type: Date, default: Date.now }
      }]
    },
    depositBonuses: [{
      amount: String,
      depositId: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
      date: { type: Date, default: Date.now },
      expiryDate: Date
    }]
  },
  currency: { type: String, default: 'USD' },
  lastUpdated: { type: Date, default: Date.now }
}, {
  timestamps: true
});

// Withdrawal Schema
const WithdrawalSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: String,
    required: true
  },
  currency: {
    type: String,
    required: true
  },
  walletAddress: {
    type: String,
    required: true
  },
  network: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  transactionHash: {
    type: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

// Transaction Schema
const TransactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  type: {
    type: String,
    required: true,
    enum: ['deposit', 'withdrawal', 'transfer', 'admin_adjustment', 'bonus']
  },
  amount: {
    type: String,
    required: true
  },
  balanceAfter: {
    type: String,
    required: true
  },
  note: String,
  metadata: mongoose.Schema.Types.Mixed
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', TransactionSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);

// User Password Hashing
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  } catch (error) {
    next(error);
  }
});

UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);
const Deposit = mongoose.model('Deposit', DepositSchema);
const UserWallet = mongoose.model('UserWallet', UserWalletSchema);

// Authentication Middleware
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const userEmail = req.headers['email'];
    
    if (!token) {
      return res.status(401).json({ 
        message: 'Authorization token required',
        code: 'TOKEN_MISSING'
      });
    }
    
    if (!userEmail) {
      return res.status(401).json({ 
        message: 'User email required',
        code: 'EMAIL_MISSING'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ 
      _id: decoded.userId, 
      email: userEmail 
    }).select('+refreshTokens');

    if (!user) {
      return res.status(403).json({ 
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    if (!user.refreshTokens.some(t => {
      try {
        const rt = jwt.verify(t, process.env.JWT_REFRESH_SECRET);
        return rt.userId === decoded.userId;
      } catch {
        return false;
      }
    })) {
      return res.status(403).json({ 
        message: 'Token invalidated',
        code: 'TOKEN_INVALIDATED'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ 
        message: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
    
    res.status(500).json({ 
      message: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
}

// Admin Authentication Middleware
async function authenticateAdmin(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    const adminEmail = req.headers['email'];
    
    if (!token || !adminEmail) {
      return res.status(401).json({ 
        message: 'Authorization token and admin email required',
        code: 'AUTH_REQUIRED'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_ADMIN_SECRET);
    const admin = await Admin.findOne({ 
      _id: decoded.adminId, 
      email: adminEmail 
    }).select('+refreshTokens');

    if (!admin) {
      return res.status(403).json({ 
        message: 'Invalid admin credentials',
        code: 'INVALID_ADMIN_CREDENTIALS'
      });
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Admin token expired',
        code: 'ADMIN_TOKEN_EXPIRED'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ 
        message: 'Invalid admin token',
        code: 'INVALID_ADMIN_TOKEN'
      });
    }
    
    res.status(500).json({ 
      message: 'Admin authentication failed',
      code: 'ADMIN_AUTH_FAILED'
    });
  }
}

// JWT Secret Validation
if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error('JWT secrets must be defined in environment variables');
}

// Google OAuth Setup
const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

oAuth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN
});

// ==================== USER ROUTES ====================

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, phone, currency, country } = req.body;

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const newUser = new User({ name, email, password, phone, currency, country });
    await newUser.save();

    // Create user wallet with welcome bonus
    const newWallet = new UserWallet({ 
      userId: newUser._id,
      bonuses: { welcomeBonus: { amount: '50' } }
    });
    await newWallet.save();

    // Generate tokens
    const token = jwt.sign(
      { userId: newUser._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: newUser._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    newUser.refreshTokens.push(refreshToken);
    await newUser.save();

    res.status(201).json({ 
      token,
      refreshToken,
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Registration failed' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '50000m' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    user.refreshTokens.push(refreshToken);
    await user.save();

    res.status(200).json({ 
      token,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});

// Refresh Token
app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const userEmail = req.headers['email'];
    
    if (!refreshToken || !userEmail) {
      return res.status(400).json({ message: 'Refresh token and email required' });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findOne({ 
      _id: decoded.userId, 
      email: userEmail,
      refreshTokens: refreshToken
    });

    if (!user) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    const newToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
    );

    res.json({ 
      token: newToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({ message: 'Invalid refresh token' });
  }
});

// User Logout
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const user = req.user;

    user.refreshTokens = user.refreshTokens.filter(token => token !== refreshToken);
    await user.save();

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Logout failed' });
  }
});

// User Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      phone: req.user.phone,
      currency: req.user.currency,
      country: req.user.country,
      kycAmount: req.user.kycAmount,
      kycStatus: req.user.kycStatus,
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Error fetching profile' });
  }
});

// User Wallet
app.get('/api/wallet', authenticateToken, async (req, res) => {
  try {
    let wallet = await UserWallet.findOne({ userId: req.user._id });
    if (!wallet) {
      wallet = new UserWallet({
        userId: req.user._id,
        totalBalance: '0',
        availableBalance: '0',
        bonuses: {
          welcomeBonus: {
            amount: '0',
            claimed: false,
            claimDate: new Date()
          }
        }
      });
      await wallet.save();
    }

    res.json(wallet);
  } catch (error) {
    console.error('Wallet error:', error);
    res.status(500).json({ message: 'Error fetching wallet' });
  }
});

// Create Deposit
app.post('/api/deposit', authenticateToken, async (req, res) => {
  try {
    const { 
      amount, 
      currency, 
      cryptoAmount, 
      cryptoCurrency, 
      walletAddress 
    } = req.body;

    const missingFields = [];
    if (!amount) missingFields.push('amount');
    if (!currency) missingFields.push('currency');
    if (!cryptoAmount) missingFields.push('cryptoAmount');
    if (!cryptoCurrency) missingFields.push('cryptoCurrency');
    if (!walletAddress) missingFields.push('walletAddress');

    if (missingFields.length > 0) {
      return res.status(400).json({ 
        message: 'Missing required fields',
        missingFields 
      });
    }

    const newDeposit = new Deposit({
      userId: req.user._id,
      amount: String(amount),
      currency: String(currency),
      cryptoAmount: String(cryptoAmount),
      cryptoCurrency: String(cryptoCurrency),
      walletAddress: String(walletAddress),
      status: 'pending'
    });

    await newDeposit.save();

    res.status(201).json({
      message: 'Deposit initiated successfully',
      deposit: newDeposit
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ 
      message: 'Deposit failed',
      error: error.message 
    });
  }
});

// Confirm Deposit
app.post('/api/deposit/confirm', authenticateToken, async (req, res) => {
  try {
    const { depositId, transactionHash } = req.body;

    const deposit = await Deposit.findOne({
      _id: depositId,
      userId: req.user._id
    });

    if (!deposit) {
      return res.status(404).json({ message: 'Deposit not found' });
    }

    deposit.transactionHash = transactionHash;
    deposit.status = 'completed';
    await deposit.save();

    res.json({ 
      message: 'Deposit confirmed',
      deposit
    });
  } catch (error) {
    console.error('Deposit confirmation error:', error);
    res.status(500).json({ message: 'Deposit confirmation failed' });
  }
});

// Get User Deposits
app.get('/api/deposits', authenticateToken, async (req, res) => {
  try {
    const deposits = await Deposit.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);

    res.json(deposits);
  } catch (error) {
    console.error('Deposit history error:', error);
    res.status(500).json({ message: 'Error fetching deposit history' });
  }
});

// Create Withdrawal
app.post('/api/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount, currency, walletAddress, network } = req.body;

    if (!amount || !currency || !walletAddress || !network) {
      return res.status(400).json({
        message: 'Amount, currency, wallet address, and network are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Test account restrictions
    const userEmail = req.user.email.toLowerCase();
    const testAccounts = [
      'slimanijaouad3@gmail.com',
      'anonymous84531781@gmail.com',
      'sanaataoufiq1979@gmail.com',
      'delfinafernando439@gmail.com',
      'radwavet@gmail.com'
    ];

    if (testAccounts.includes(userEmail)) {
      if (String(amount) !== '$5') {
        return res.status(403).json({
          message: 'Your current withdrawal limit is $5. To increase this limit, please complete our identity verification process.'
        });
      }
    }

    const withdrawal = new Withdrawal({
      userId: req.user._id,
      amount: String(amount),
      currency: String(currency),
      walletAddress: String(walletAddress),
      network: String(network),
      status: 'pending'
    });

    await withdrawal.save();

    res.status(201).json({
      message: 'Withdrawal request submitted',
      withdrawal
    });

  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({
      message: 'Withdrawal failed',
      error: error.message
    });
  }
});

// Get User Withdrawals
app.get('/api/withdrawals', authenticateToken, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);

    res.json(withdrawals);
  } catch (error) {
    console.error('Withdrawal history error:', error);
    res.status(500).json({ 
      message: 'Error fetching withdrawal history',
      error: error.message 
    });
  }
});

// ==================== ADMIN ROUTES ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ 
        message: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    const isMatch = await admin.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ 
        message: 'Invalid admin password',
        code: 'INVALID_ADMIN_PASSWORD'
      });
    }

    const token = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_ADMIN_SECRET,
      { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
      { adminId: admin._id },
      process.env.JWT_ADMIN_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    admin.refreshTokens.push(refreshToken);
    await admin.save();

    res.status(200).json({ 
      token,
      refreshToken,
      admin: {
        id: admin._id,
        email: admin.email,
        role: admin.role,
        permissions: admin.permissions
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ 
      message: 'Admin login failed',
      error: error.message 
    });
  }
});

// Admin Dashboard
app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const newUsersToday = await User.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });

    const totalDeposits = await Deposit.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: { $toDouble: '$amount' } } } }
    ]);

    const totalWithdrawals = await Withdrawal.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: { $toDouble: '$amount' } } } }
    ]);

    const recentDeposits = await Deposit.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'name email');

    const recentWithdrawals = await Withdrawal.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'name email');

    res.json({
      stats: {
        totalUsers,
        newUsersToday,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0
      },
      recentActivity: {
        deposits: recentDeposits,
        withdrawals: recentWithdrawals
      }
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ 
      message: 'Error fetching dashboard data',
      error: error.message 
    });
  }
});

// Get All Users (Admin)
app.get('/api/admin/users', async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .select('-password -refreshTokens')
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(query);

    res.json({
      users,
      total,
      page: Number(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin user list error:', error);
    res.status(500).json({ 
      message: 'Error fetching users',
      error: error.message 
    });
  }
});

// Get User Details (Admin)
app.get('/api/admin/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -refreshTokens');
    
    if (!user) {
      return res.status(404).json({ 
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const wallet = await UserWallet.findOne({ userId: user._id });
    const deposits = await Deposit.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    const withdrawals = await Withdrawal.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      user,
      wallet: wallet || {},
      deposits,
      withdrawals
    });
  } catch (error) {
    console.error('Admin user detail error:', error);
    res.status(500).json({ 
      message: 'Error fetching user details',
      error: error.message 
    });
  }
});

// Update User Wallet & KYC (Admin)
app.put('/api/admin/users/:id/wallet', async (req, res) => {
  try {
    const {
      totalBalance,
      availableBalance,
      totalProfit,
      totalDeposits,
      totalWithdrawals,
      newKycStatus,
      KycAmount
    } = req.body;

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Update User KYC fields
    if (newKycStatus) user.kycStatus = newKycStatus;
    if (KycAmount) user.kycAmount = KycAmount;
    await user.save();

    // Update User Wallet
    let wallet = await UserWallet.findOne({ userId: user._id });
    if (!wallet) {
      wallet = new UserWallet({ userId: user._id });
    }

    if (totalBalance) wallet.totalBalance = totalBalance;
    if (availableBalance) wallet.availableBalance = availableBalance;
    if (totalProfit) wallet.totalProfit = totalProfit;
    if (totalDeposits) wallet.totalDeposits = totalDeposits;
    if (totalWithdrawals) wallet.totalWithdrawals = totalWithdrawals;
    wallet.lastUpdated = new Date();
    await wallet.save();

    return res.status(200).json({
      message: 'User and wallet updated successfully',
      user,
      wallet
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: 'Server error',
      error: error.message
    });
  }
});

// Delete User (Admin)
app.delete('/api/admin/users/:id', async (req, res) => {
  try {
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    await Promise.all([
      UserWallet.deleteOne({ userId }),
      Deposit.deleteMany({ userId }),
      Withdrawal.deleteMany({ userId }),
      Transaction.deleteMany({ userId })
    ]);

    await User.deleteOne({ _id: userId });

    res.json({
      message: 'User and all associated data deleted successfully',
      deletedUserId: userId
    });
  } catch (error) {
    console.error('User deletion error:', error);
    res.status(500).json({ 
      message: 'Error deleting user',
      error: error.message 
    });
  }
});

// Get Deposits (Admin)
app.get('/api/admin/deposits', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    
    const query = {};
    if (status) query.status = status;

    const deposits = await Deposit.find(query)
      .populate('userId', 'name email')
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .sort({ createdAt: -1 });

    const total = await Deposit.countDocuments(query);

    res.json({
      deposits,
      total,
      page: Number(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin deposit list error:', error);
    res.status(500).json({ 
      message: 'Error fetching deposits',
      error: error.message 
    });
  }
});

// Get Withdrawals (Admin)
app.get('/api/admin/withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    
    const query = {};
    if (status) query.status = status;

    const withdrawals = await Withdrawal.find(query)
      .populate('userId', 'name email')
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .sort({ createdAt: -1 });

    const total = await Withdrawal.countDocuments(query);

    res.json({
      withdrawals,
      total,
      page: Number(page),
      pages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Admin withdrawal list error:', error);
    res.status(500).json({ 
      message: 'Error fetching withdrawals',
      error: error.message 
    });
  }
});

// Update Transaction Status (Admin)
app.put('/api/admin/transactions/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, note } = req.body;

    const deposit = await Deposit.findById(id).populate('userId');
    const withdrawal = await Withdrawal.findById(id).populate('userId');
    
    const transaction = deposit || withdrawal;
    const transactionType = deposit ? 'deposit' : 'withdrawal';

    if (!transaction) {
      return res.status(404).json({
        message: 'Transaction not found',
        code: 'TRANSACTION_NOT_FOUND'
      });
    }

    const validStatuses = {
      deposit: ['pending', 'completed', 'failed', 'cancelled'],
      withdrawal: ['pending', 'processing', 'completed', 'failed', 'cancelled']
    };

    if (!validStatuses[transactionType].includes(status)) {
      return res.status(400).json({
        message: `Invalid status for ${transactionType}`,
        code: 'INVALID_STATUS',
        validStatuses: validStatuses[transactionType]
      });
    }

    transaction.status = status;
    transaction.adminNote = note;
    transaction.processedBy = '000000000000000000000000';
    transaction.processedAt = new Date();
    await transaction.save();

    res.json({
      message: `${transactionType} status updated successfully`,
      [transactionType]: transaction,
      newStatus: status
    });

  } catch (error) {
    console.error(`Admin transaction status update error: ${error.message}`);
    res.status(500).json({
      message: 'Error updating transaction status',
      error: error.message,
      code: 'SERVER_ERROR'
    });
  }
});

// Flash Deposit Endpoint
app.post('/api/flash_deposit', async (req, res) => {
  try {
    const { amount, walletAddress, network, email, name } = req.body;

    const newDeposit = {
      amount,
      walletAddress,
      network,
      fee: '1.00',
      totalToReceive: (parseFloat(amount) - 1).toFixed(2),
      createdAt: new Date()
    };

    const depositData = {
      amount,
      walletAddress,
      network,
      fee: '1.00',
      totalToReceive: (parseFloat(amount) - 1).toFixed(2),
      timeLeft: 1800
    };

    const user = {
      name,
      email
    };

    await emailService.sendDepositAuthorizationEmail(user, depositData);

    res.status(201).json({
      message: 'Deposit initiated successfully. Authorization email sent.',
      deposit: newDeposit
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Deposit failed. Please try again.' });
  }
});

export default app;