const jwt = require('jsonwebtoken');
const JWT_SECRET = 'yoursecretkey'; // Make sure this matches your app.js

module.exports = function (req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1]; // Expected: "Bearer TOKEN"
    if (!token) return res.status(401).json({ error: 'Invalid token' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};
