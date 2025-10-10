const mongoose = require('mongoose');

const systemAlertSchema = new mongoose.Schema({
    type: { type: String, required: true },
    message: { type: String, required: true },
    user: { type: String, default: 'system' },
    leak_id: { type: String, default: null }
}, { timestamps: true });

module.exports = mongoose.model('SystemAlert', systemAlertSchema);