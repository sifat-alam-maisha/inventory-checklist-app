const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');  // Required for serving the HTML file

const User = require('./models/User');
const Item = require('./models/Item');
const connectDb = require('./db');  // Import the MongoDB connection Singleton

const JWT_SECRET = 'yoursecretkey';          // TODO: put in .env for production
const tokenBlacklist = new Set();            // simple in-memory blacklist for logout
const passwordResetTokens = {};              // in-memory reset tokens {token:{userId,expires}}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));           // serves public/*.html

/* ---------------- DB ---------------- */
connectDb();  // Establish MongoDB connection using Singleton pattern

/* -------------- Auth Middleware -------------- */
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  if (tokenBlacklist.has(token)) return res.status(401).json({ error: 'Token has been logged out' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* -------------- User Routes -------------- */

// Register
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existing = await User.findOne({ $or: [{ username }, { email }] });
    if (existing) return res.status(400).json({ error: 'Username or email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashed });
    await user.save();
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Wrong password' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Logout
app.post('/logout', (req, res) => {
  const header = req.headers.authorization || '';
  const token = header.split(' ')[1];
  if (token) tokenBlacklist.add(token);
  res.json({ message: 'Logged out successfully' });
});

/* -------- Forgot / Reset Password (Demo via Gmail) -------- */
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  // Always respond success to avoid disclosing if email exists
  if (!user) return res.json({ message: 'If your email is registered, a reset link has been sent.' });

  const resetToken = crypto.randomBytes(32).toString('hex');
  passwordResetTokens[resetToken] = { userId: user._id, expires: Date.now() + 60 * 60 * 1000 }; // 1 hour

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'your_email@gmail.com',       // <-- change to your Gmail
      pass: 'your_gmail_app_password',    // <-- change to Gmail App Password
    },
  });

  const resetLink = `http://localhost:3000/reset-password.html?token=${resetToken}`;

  try {
    await transporter.sendMail({
      from: 'your_email@gmail.com',
      to: email,
      subject: 'Password Reset',
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password.<br/>This link expires in 1 hour.</p>`,
    });
    res.json({ message: 'If your email is registered, a reset link has been sent.' });
  } catch (err) {
    console.error('Email send failed:', err);
    res.status(500).json({ error: 'Failed to send reset email.' });
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const record = passwordResetTokens[token];
  if (!record || Date.now() > record.expires) {
    return res.status(400).json({ error: 'Token expired or invalid' });
  }
  const user = await User.findById(record.userId);
  if (!user) return res.status(400).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();
  delete passwordResetTokens[token];
  res.json({ message: 'Password reset successful. You can now log in.' });
});

/* -------------- Inventory Routes (Protected) -------------- */

function computeStatus(qty) { return (Number(qty) || 0) > 0 ? 'In Stock' : 'Out of Stock'; }

// Create item (quantity clamped to ≥0, status auto)
app.post('/items', authMiddleware, async (req, res) => {
  try {
    let { name, category, quantity } = req.body;
    quantity = Math.max(0, Number(quantity) || 0);
    const status = computeStatus(quantity);

    const item = new Item({ name, category, quantity, status, userId: req.userId });
    await item.save();
    res.status(201).json(item);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get all items (newest first)
app.get('/items', authMiddleware, async (req, res) => {
  try {
    const items = await Item.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update item (recompute status from quantity)
app.put('/items/:id', authMiddleware, async (req, res) => {
  try {
    let { name, category, quantity } = req.body;
    if (quantity !== undefined) {
      quantity = Math.max(0, Number(quantity) || 0);
    }
    const updates = { name, category };
    if (quantity !== undefined) {
      updates.quantity = quantity;
      updates.status = computeStatus(quantity);
    }

    const item = await Item.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      updates,
      { new: true }
    );
    if (!item) return res.status(404).json({ error: 'Item not found' });
    res.json(item);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Delete item
app.delete('/items/:id', authMiddleware, async (req, res) => {
  try {
    const deleted = await Item.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!deleted) return res.status(404).json({ error: 'Item not found' });
    res.json({ message: 'Item deleted successfully!' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Manually set status (if you use a stock management page)
app.put('/items/:id/status', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body; // 'In Stock' or 'Out of Stock'
    if (!['In Stock', 'Out of Stock'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    const item = await Item.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { status },
      { new: true }
    );
    if (!item) return res.status(404).json({ error: 'Item not found' });
    res.json(item);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Unique item names (no duplicates)
app.get('/items/names', authMiddleware, async (req, res) => {
  try {
    const items = await Item.find({ userId: req.userId }).select('name');
    const unique = [...new Set(items.map(i => (i.name || '').trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    res.json(unique);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve item names HTML
app.get('/item-names.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'item-names.html'));
});

/* -------------- Start -------------- */
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
