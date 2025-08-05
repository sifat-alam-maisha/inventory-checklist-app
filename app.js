const express = require('express');
const mongoose = require('mongoose');
const auth = require('./middleware/auth');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const User = require('./models/User');
const Item = require('./models/Item');

const JWT_SECRET = 'yoursecretkey'; // Use your own secret!
const tokenBlacklist = [];
const passwordResetTokens = {}; // For reset password

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/inventory-checklist', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => console.error('❌ MongoDB connection error:', err));

// =======================
// 1. AUTH MIDDLEWARE
// =======================
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (tokenBlacklist.includes(token)) return res.status(401).json({ error: 'Token has been logged out' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        req.userId = user.userId;
        next();
    });
}

// =======================
// 2. USER ROUTES
// =======================

// Register
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const existing = await User.findOne({ $or: [ { username }, { email } ] });
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

// Logout (JWT Blacklist)
app.post('/logout', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(400).json({ error: 'No token found' });

    const token = authHeader.split(' ')[1];
    tokenBlacklist.push(token);
    res.json({ message: 'Logged out successfully' });
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(200).json({ message: 'If your email is registered, a reset link has been sent.' });

    // Generate secure token (expires in 1 hour)
    const resetToken = crypto.randomBytes(32).toString('hex');
    passwordResetTokens[resetToken] = { userId: user._id, expires: Date.now() + 3600000 };

    // Send email
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'your_email@gmail.com', // <-- Your Gmail address
            pass: 'your_gmail_app_password' // <-- Your Gmail App Password (NOT your login password)
        }
    });

    const resetLink = `http://localhost:3000/reset-password.html?token=${resetToken}`;
    try {
        await transporter.sendMail({
            from: 'your_email@gmail.com',
            to: email,
            subject: 'Password Reset',
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password.<br>This link expires in 1 hour.</p>`
        });
        res.json({ message: 'If your email is registered, a reset link has been sent.' });
    } catch (err) {
        console.error('Email sending failed:', err);
        res.status(500).json({ error: 'Failed to send reset email.' });
    }
});

// Reset Password
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const data = passwordResetTokens[token];
    if (!data || Date.now() > data.expires) {
        return res.status(400).json({ error: 'Token expired or invalid' });
    }
    const user = await User.findById(data.userId);
    if (!user) return res.status(400).json({ error: 'User not found' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    delete passwordResetTokens[token];
    res.json({ message: 'Password reset successful. You can now log in.' });
});

// Create Item (auto status by quantity)
app.post('/items', auth, async (req, res) => {
    try {
        const { name, category, quantity } = req.body;
        const status = (quantity > 0) ? "In Stock" : "Out of Stock";
        const item = new Item({ name, category, quantity, status, userId: req.userId });
        await item.save();
        res.status(201).json(item);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Get all items for user
app.get('/items', auth, async (req, res) => {
    const items = await Item.find({ userId: req.userId });
    res.json(items);
});

// Update item (auto update status based on quantity)
app.put('/items/:id', auth, async (req, res) => {
    try {
        const { name, category, quantity } = req.body;
        const status = (quantity > 0) ? "In Stock" : "Out of Stock";
        const item = await Item.findOneAndUpdate(
            { _id: req.params.id, userId: req.userId },
            { name, category, quantity, status },
            { new: true }
        );
        if (!item) return res.status(404).json({ error: 'Item not found' });
        res.json(item);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Delete item
app.delete('/items/:id', auth, async (req, res) => {
    try {
        const deletedItem = await Item.findOneAndDelete({ _id: req.params.id, userId: req.userId });
        if (!deletedItem) return res.status(404).json({ error: 'Item not found' });
        res.json({ message: 'Item deleted successfully!' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Manually update status (for stock.html)
app.put('/items/:id/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
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


// =======================
// 3. INVENTORY ROUTES (Protected)
// =======================

// Add new item
app.post('/items', authMiddleware, async (req, res) => {
    try {
        const { name, category, quantity, status } = req.body;
        const item = new Item({
            name,
            category,
            quantity,
            status: status || 'In Stock',
            userId: req.userId,
        });
        await item.save();
        res.status(201).json(item);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Get all items for logged in user
app.get('/items', authMiddleware, async (req, res) => {
    try {
        const items = await Item.find({ userId: req.userId });
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update item by id (PUT)
app.put('/items/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const updatedItem = await Item.findOneAndUpdate(
            { _id: id, userId: req.userId },
            req.body,
            { new: true }
        );
        if (!updatedItem) return res.status(404).json({ error: 'Item not found' });
        res.json(updatedItem);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Delete item by id
app.delete('/items/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const deletedItem = await Item.findOneAndDelete({ _id: id, userId: req.userId });
        if (!deletedItem) return res.status(404).json({ error: 'Item not found' });
        res.json({ message: 'Item deleted successfully!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ======= UPDATE STATUS FEATURE =======
app.put('/items/:id/status', authMiddleware, async (req, res) => {
    try {
        const { status } = req.body; // "In Stock" or "Out of Stock"
        const item = await Item.findOneAndUpdate(
            { _id: req.params.id, userId: req.userId },
            { status },
            { new: true }
        );
        if (!item) return res.status(404).json({ error: 'Item not found' });
        res.json(item);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// =======================
// 4. TEST ROUTE (OPTIONAL)
// =======================
app.get('/', (req, res) => {
    res.send('Inventory Checklist API is working!');
});

// =======================
// 5. START SERVER
// =======================
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
