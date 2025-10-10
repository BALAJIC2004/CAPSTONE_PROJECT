const mongoose = require('mongoose');

const leakSchema = new mongoose.Schema({
    zone_id: { type: String, required: true },
    location: { type: String, required: true },
    severity: { type: String, enum: ['low', 'medium', 'high'], required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['reported', 'investigating', 'fixed'], default: 'reported' },
    reported_by: { type: String, required: true },
    assigned_to: { type: String, default: null },
    field_notes: { type: String, default: null },
    media_file: { type: String, default: null },
    media_type: { type: String, default: null },
    coordinates: {
        latitude: { type: Number, default: null },
        longitude: { type: Number, default: null }
    }
}, { timestamps: true });

module.exports = mongoose.model('Leak', leakSchema);