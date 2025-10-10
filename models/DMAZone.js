const mongoose = require('mongoose');

const dmaZoneSchema = new mongoose.Schema({
    zone_id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    location: { type: String, required: true },
    connections: { type: Number, required: true },
    nrw: { type: Number, default: 0 }
}, { timestamps: true });

module.exports = mongoose.model('DMAZone', dmaZoneSchema);