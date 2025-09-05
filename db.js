// db.js
const mongoose = require('mongoose');

let isConnected = false;  // Track if connection has been established

const connectDb = async () => {
  // If a connection already exists, return immediately
  if (isConnected) {
    console.log('✅ Already connected to MongoDB');
    return;
  }

  // Otherwise, establish a new connection
  try {
    await mongoose.connect('mongodb://localhost:27017/inventory-checklist', {
      useNewUrlParser: true,  // This option is now part of the default behavior
      useUnifiedTopology: true,  // This option is also part of the default behavior
    });
    isConnected = true;  // Mark the connection as established
    console.log('✅ Connected to MongoDB');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);  // Exit the process if connection fails
  }
};

module.exports = connectDb;  // Export the connectDb function
