const mongoose = require('mongoose');

const itemSchema = new mongoose.Schema({
    name: String,
    category: String,
    quantity: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        default: "In Stock"
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }
}, { timestamps: true });

module.exports = mongoose.model('Item', itemSchema);
