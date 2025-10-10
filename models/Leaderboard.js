const mongoose = require('mongoose');

const leaderboardSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    leaks_reported: { type: Number, default: 0 },
    leaks_verified: { type: Number, default: 0 },
    points: { type: Number, default: 0 },
    rank: { type: Number, default: 999 },
    badges: [{ type: String }]
}, { timestamps: true });

module.exports = mongoose.model('Leaderboard', leaderboardSchema);