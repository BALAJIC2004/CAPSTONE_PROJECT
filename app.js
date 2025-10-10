const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const connectDB = require('./config/database');
const User = require('./models/User');
const DMAZone = require('./models/DMAZone');
const Leak = require('./models/Leak');
const app = express();
require('dotenv').config();
const PORT = 3000;

connectDB();


// Create default users if they don't exist
async function createDefaultUsers() {
    try {
        // const users = [
        //     { username: 'admin', password: bcrypt.hashSync('admin123', 10), role: 'dma_staff', name: 'System Admin' },
        //     { username: 'field_tech', password: bcrypt.hashSync('tech123', 10), role: 'field_team', name: 'Field Technician' },
        //     { username: 'user', password: bcrypt.hashSync('user123', 10), role: 'public_user', name: 'Public User' }
        // ];

        const users = [
            { username: 'admin', password: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10), role: 'dma_staff', name: 'System Admin' },
            { username: 'field_tech', password: bcrypt.hashSync(process.env.FIELD_PASSWORD, 10), role: 'field_team', name: 'Field Technician' },
            { username: 'user', password: bcrypt.hashSync(process.env.USER_PASSWORD, 10), role: 'public_user', name: 'Public User' }
        ];

        for (const userData of users) {
            const exists = await User.findOne({ username: userData.username });
            if (!exists) {
                await User.create(userData);
                console.log(`✅ Created user: ${userData.username}`);
            }
        }
    } catch (error) {
        console.error('Error creating default users:', error);
    }
}
// Call this after database connection
setTimeout(createDefaultUsers, 2000);


// Add sample DMA zones to fix NaN%
async function addSampleData() {
    const count = await DMAZone.countDocuments();
    if (count === 0) {
        await DMAZone.create([
            { zone_id: 'DMA_001', name: 'City Center', location: 'Downtown', connections: 1500, nrw: 35 },
            { zone_id: 'DMA_002', name: 'Industrial Zone', location: 'East Area', connections: 800, nrw: 25 },
            { zone_id: 'DMA_003', name: 'Residential North', location: 'North Side', connections: 2000, nrw: 15 }
        ]);
        console.log('✅ Sample DMA zones added');
    }
}
setTimeout(addSampleData, 3000);


// Configure file upload storage - (Image/Video)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'public/uploads/leaks';
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Generate unique filename with timestamp
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

// File filter for images and videos
const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|avi|mov|mkv|webm/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb(new Error('Only image and video files are allowed'));
    }
};
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    fileFilter: fileFilter
});
// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'jal-rakshak-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));
app.set('view engine', 'ejs');

// Sample Data

let leaks = [];
let systemAlerts = [];
let dmaZones = [
    { id: 'DMA_001', name: 'City Center', location: 'Downtown Area', connections: 1500, nrw: 45, lastUpdate: new Date() },
    { id: 'DMA_002', name: 'Industrial Zone', location: 'East Industrial Area', connections: 800, nrw: 28, lastUpdate: new Date() },
    { id: 'DMA_003', name: 'Residential North', location: 'North Residential', connections: 2000, nrw: 15, lastUpdate: new Date() }
];

// Authentication Middleware
function requireAuth(requiredRole = null) {
    return (req, res, next) => {
        if (!req.session.user) {
            return res.redirect('/login');
        }
        if (requiredRole && req.session.user.role !== requiredRole) {
            return res.status(403).render('pages/error', {
                message: 'Access denied. Insufficient permissions.'
            });
        }
        next();
    };
}

// Reset to original working passwords
// app.get('/panic-fix', async (req, res) => {
//     try {
//         // Delete all existing users
//         await User.deleteMany({});

//         // Create users with original passwords
//         await User.create([
//             { 
//                 username: 'admin', 
//                 password: bcrypt.hashSync('admin123', 10), 
//                 role: 'dma_staff', 
//                 name: 'System Admin' 
//             },
//             { 
//                 username: 'field_tech', 
//                 password: bcrypt.hashSync('tech123', 10), 
//                 role: 'field_team', 
//                 name: 'Field Technician' 
//             },
//             { 
//                 username: 'user', 
//                 password: bcrypt.hashSync('user123', 10), 
//                 role: 'public_user', 
//                 name: 'Public User' 
//             }
//         ]);

//         console.log('✅ USERS RESET TO ORIGINAL PASSWORDS!');
//         res.send(`
//             <h1>✅ LOGIN FIXED - USE ORIGINAL PASSWORDS</h1>
//             <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
//                 <h3>Login Credentials:</h3>
//                 <p><strong>Admin:</strong> admin / admin123</p>
//                 <p><strong>Field Tech:</strong> field_tech / tech123</p>
//                 <p><strong>User:</strong> user / user123</p>
//             </div>
//             <br>
//             <a href="/login" style="padding: 10px 20px; background: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">GO TO LOGIN</a>
//         `);
//     } catch (error) {
//         console.error('Reset error:', error);
//         res.send(`
//             <h1>❌ Error - Manual Reset Needed</h1>
//             <p>Stop server and run in terminal:</p>
//             <code>mongosh</code><br>
//             <code>use jalrakshak</code><br>
//             <code>db.users.deleteMany({})</code><br>
//             <code>exit</code><br>
//             <p>Then restart server.</p>
//         `);
//     }
// });

// Routes
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Login Routes
app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('pages/login', { error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = user;
            return res.redirect('/dashboard');
        } else {
            res.render('pages/login', { error: 'Invalid username or password' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.render('pages/login', { error: 'Login failed' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Dashboard - Accessible to all authenticated users
app.get('/dashboard', requireAuth(), async (req, res) => {
    try {
        const dmaZones = await DMAZone.find();
        const leaks = await Leak.find();
        
        // REAL NRW CALCULATION based on leaks
        const formattedZones = dmaZones.map(zone => {
            const zoneLeaks = leaks.filter(leak => leak.zone_id === zone.zone_id);
            const activeLeaks = zoneLeaks.filter(leak => leak.status !== 'fixed').length;
            
            // Calculate NRW% based on active leaks (1 leak = +5% NRW)
            const baseNrw = 15; // Base NRW without leaks
            const leakImpact = activeLeaks * 5; // Each active leak adds 5%
            const calculatedNrw = Math.min(80, baseNrw + leakImpact);
            
            return {
                zone_id: zone.zone_id,
                name: zone.name,
                location: zone.location,
                connections: zone.connections,
                nrw: parseFloat(calculatedNrw.toFixed(1)), // Round to 1 decimal
                updatedAt: zone.updatedAt,
                activeLeaks: activeLeaks
            };
        });

        const activeLeaks = await Leak.countDocuments({ status: 'reported' });
        
        // Calculate average NRW
        const totalNRW = formattedZones.reduce((sum, zone) => sum + zone.nrw, 0);
        const averageNRW = formattedZones.length > 0 ? totalNRW / formattedZones.length : 0;

        const waterSaved = Math.round((averageNRW / 100) * 5000000);
        
        res.render('pages/dashboard', {
            user: req.session.user,
            totalNRW: averageNRW.toFixed(1),
            activeLeaks: activeLeaks,
            dmaZones: formattedZones,
            waterSaved: waterSaved,
            systemAlerts: systemAlerts.slice(-5).reverse()
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).send('Server error');
    }
});

// DMA Zones Routes
app.get('/dma-zones', requireAuth('dma_staff'), async (req, res) => {
    try {
        const dmaZones = await DMAZone.find();
        res.render('pages/dma-zones', {
            user: req.session.user,
            dmaZones: dmaZones
        });
    } catch (error) {
        console.error('DMA zones error:', error);
        res.status(500).send('Server error');
    }
});

app.post('/dma-zones', requireAuth('dma_staff'), async (req, res) => {
    try {
        const { zone_id, name, location, connections } = req.body;
        const newZone = new DMAZone({
            zone_id,
            name,
            location,
            connections: parseInt(connections),
            nrw: Math.floor(Math.random() * 40) + 10
        });
        await newZone.save();
        res.redirect('/dma-zones');
    } catch (error) {
        console.error('Add DMA zone error:', error);
        res.status(500).send('Server error');
    }
});

// Delete DMA Zone - FIXED
app.post('/dma-zones/delete/:zoneId', requireAuth('dma_staff'), async (req, res) => {
    try {
        const zoneId = req.params.zoneId;
        console.log('Deleting zone:', zoneId);

        const result = await DMAZone.findOneAndDelete({ zone_id: zoneId });

        if (result) {
            console.log('✅ Zone deleted:', zoneId);
        } else {
            console.log('❌ Zone not found:', zoneId);
        }

        res.redirect('/dma-zones');
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).send('Delete failed');
    }
});


// Leak Reports - Different views based on role - FIXED
app.get('/leaks', requireAuth(), async (req, res) => {
    const user = req.session.user;

    try {
        console.log('Leaks page accessed by:', user.username, 'role:', user.role);

        // Public users see their own reports
        if (user.role === 'public_user') {
            const userLeaks = await Leak.find({ reported_by: user.username });
            const dmaZones = await DMAZone.find();

            return res.render('pages/leaks-public', {
                user: user,
                leaks: userLeaks,
                dmaZones: dmaZones
            });
        }

        // Field team sees field management view
        if (user.role === 'field_team') {
            const allLeaks = await Leak.find().sort({ createdAt: -1 });
            return res.render('pages/leaks-field-team', {
                user: user,
                leaks: allLeaks
            });
        }

        // DMA Staff (admin) sees full management view
        if (user.role === 'dma_staff') {
            const allLeaks = await Leak.find().sort({ createdAt: -1 });
            return res.render('pages/leaks-staff', {
                user: user,
                leaks: allLeaks
            });
        }


        res.redirect('/dashboard');

    } catch (error) {
        console.error('❌ Leaks route ERROR:', error);
        res.status(500).send('Error loading leaks page: ' + error.message);
    }
});


// Public user reports leak with file upload and location
app.post('/leaks/report', requireAuth(), upload.single('media_file'), async (req, res) => {
    try {
        const { zone_id, location, severity, description, latitude, longitude } = req.body;

        const newLeak = new Leak({
            zone_id: zone_id,
            location: location,
            severity: severity,
            description: description || 'No description provided',
            status: 'reported',
            reported_by: req.session.user.username,
            media_file: req.file ? `/uploads/leaks/${req.file.filename}` : null,
            media_type: req.file ? (req.file.mimetype.startsWith('video/') ? 'video' : 'image') : null,
            coordinates: {
                latitude: latitude ? parseFloat(latitude) : null,
                longitude: longitude ? parseFloat(longitude) : null
            }
        });

        await newLeak.save();
        systemAlerts.push({
            type: 'leak_reported',
            message: `New ${severity} leak reported in ${zone_id} by ${req.session.user.username}`,
            timestamp: new Date().toLocaleString()
        });
        console.log('✅ New leak reported:', newLeak._id);

        res.redirect('/leaks');
    } catch (error) {
        console.error('Leak report error:', error);
        res.status(500).send('Leak report failed');
    }
});


app.post('/leaks/field-update/:leakId', requireAuth('field_team'), async (req, res) => {
    try {
        const leakId = req.params.leakId;
        const { status, field_notes } = req.body;

        const leak = await Leak.findById(leakId);
        await Leak.findByIdAndUpdate(leakId, {
            status: status,
            field_notes: field_notes,
            assigned_to: req.session.user.name,
            updatedAt: new Date()
        });

        // GIVE POINTS TO USER WHEN LEAK IS VERIFIED/FIXED
        if (status === 'investigating' || status === 'fixed') {
            await updateLeaderboard(leak.reported_by, leak.reported_by, 'verified');
        }

        systemAlerts.push({
            type: 'status_updated',
            message: `Field team updated leak in ${leak.zone_id} to ${status}`,
            timestamp: new Date().toLocaleString()
        });

        res.redirect('/leaks');
    } catch (error) {
        console.error('Field update error:', error);
        res.status(500).send('Update failed');
    }
});


// Assign leak to field team with alerts
app.post('/leaks/assign/:leakId', requireAuth('field_team'), async (req, res) => {
    try {
        const leakId = req.params.leakId;
        const leak = await Leak.findById(leakId);

        await Leak.findByIdAndUpdate(leakId, {
            assigned_to: req.session.user.name,
            status: 'investigating',
            updatedAt: new Date()
        });

        // ADD SYSTEM ALERT
        systemAlerts.push({
            type: 'leak_assigned',
            message: `Leak in ${leak.zone_id} assigned to ${req.session.user.name}`,
            timestamp: new Date().toLocaleString()
        });

        console.log('✅ Leak assigned with alert');
        res.redirect('/leaks');
    } catch (error) {
        console.error('Assign error:', error);
        res.status(500).send('Assign failed');
    }
});


// User deletes their own leak report - FIXED
app.post('/leaks/delete/:leakId', requireAuth(), async (req, res) => {
    try {
        const leakId = req.params.leakId;
        const user = req.session.user;

        console.log('Delete attempt by:', user.username, 'for leak:', leakId);


        const leak = await Leak.findById(leakId);

        if (!leak) {
            console.log('Leak not found:', leakId);
            return res.redirect('/leaks');
        }

        // Check if user owns this leak or is staff
        if (leak.reported_by === user.username || user.role === 'dma_staff') {
            await Leak.findByIdAndDelete(leakId);
            console.log('✅ Leak deleted successfully:', leakId);
        } else {
            console.log('❌ Permission denied for user:', user.username);
        }

        res.redirect('/leaks');
    } catch (error) {
        console.error('Delete leak error:', error);
        res.status(500).send('Delete failed');
    }
});


//LeaderBoard Section
const Leaderboard = require('./models/Leaderboard');

// Leaderboard route
app.get('/leaderboard', requireAuth(), async (req, res) => {
    try {
        const leaderboard = await Leaderboard.find().sort({ points: -1 }).limit(50);
        res.render('pages/leaderboard', {
            user: req.session.user,
            sessionUser: req.session.user,
            leaderboard: leaderboard
        });
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).send('Leaderboard loading failed');
    }
});

app.post('/leaks/report', requireAuth(), upload.single('media_file'), async (req, res) => {
    try {
        const { zone_id, location, severity, description, latitude, longitude } = req.body;

        const newLeak = new Leak({
            zone_id: zone_id,
            location: location,
            severity: severity,
            description: description || 'No description provided',
            status: 'reported',
            reported_by: req.session.user.username,
            media_file: req.file ? `/uploads/leaks/${req.file.filename}` : null,
            media_type: req.file ? (req.file.mimetype.startsWith('video/') ? 'video' : 'image') : null,
            coordinates: {
                latitude: latitude ? parseFloat(latitude) : null,
                longitude: longitude ? parseFloat(longitude) : null
            }
        });

        await newLeak.save();

        // UPDATE LEADERBOARD
        await updateLeaderboard(req.session.user.username, req.session.user.name, 'report');

        // System alert
        systemAlerts.push({
            type: 'leak_reported',
            message: `New ${severity} leak reported in ${zone_id} by ${req.session.user.username} +10 points!`,
            timestamp: new Date().toLocaleString()
        });

        res.redirect('/leaks');
    } catch (error) {
        console.error('Leak report error:', error);
        res.status(500).send('Leak report failed');
    }
});


// Leaderboard update function
async function updateLeaderboard(username, name, action) {
    try {
        let userStats = await Leaderboard.findOne({ username });

        if (!userStats) {
            userStats = new Leaderboard({ username, name });
        }

        // Update based on action
        switch (action) {
            case 'report':
                userStats.leaks_reported += 1;
                userStats.points += 10;
                break;
            case 'verified':
                userStats.leaks_verified += 1;
                userStats.points += 5;
                break;
        }

        // Award badges
        await awardBadges(userStats);

        await userStats.save();
        await updateRanks();

        console.log(`🏆 Leaderboard updated: ${username} - ${action}`);
    } catch (error) {
        console.error('Leaderboard update error:', error);
    }
}

// Award badges based on achievements
async function awardBadges(userStats) {
    const badges = [];

    if (userStats.leaks_reported >= 1) badges.push('first_report');
    if (userStats.leaks_reported >= 5) badges.push('reporter_novice');
    if (userStats.leaks_reported >= 10) badges.push('reporter_expert');
    if (userStats.leaks_reported >= 20) badges.push('water_guardian');
    if (userStats.leaks_verified >= 5) badges.push('verified_helper');
    if (userStats.points >= 100) badges.push('water_hero');

    // Remove duplicates and update
    userStats.badges = [...new Set([...userStats.badges, ...badges])];
}

// Update ranks based on points
async function updateRanks() {
    const allUsers = await Leaderboard.find().sort({ points: -1 });

    for (let i = 0; i < allUsers.length; i++) {
        allUsers[i].rank = i + 1;
        await allUsers[i].save();
    }
}


                                                                                                                                                                                            
// Graph Analytics Route - WITH ERROR HANDLING
app.get('/graph', requireAuth(), async (req, res) => {
    try {
        const leaks = await Leak.find();
        const dmaZones = await DMAZone.find();
        
        // Initialize with empty data
        let dmaLeakData = { labels: [], counts: [] };
        let monthlyData = { months: [], counts: [] };
        let totalLeaks = 0;
        let dmaZonesCount = 0;
        let activeUsers = 0;

        try {
            // Graph 1: DMA Zone Leak Distribution
            dmaLeakData = {
                labels: [],
                counts: []
            };

            // Count real leaks for each DMA zone
            for (const zone of dmaZones) {
                const leakCount = await Leak.countDocuments({ zone_id: zone.zone_id });
                dmaLeakData.labels.push(zone.zone_id);
                dmaLeakData.counts.push(leakCount);
            }

            // Graph 2: Monthly Leak Reports
            monthlyData = {
                months: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
                counts: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            };

            // Count real leaks by month
            for (const leak of leaks) {
                if (leak.createdAt) {
                    const month = leak.createdAt.getMonth();
                    monthlyData.counts[month]++;
                }
            }

            // Calculate real metrics
            totalLeaks = leaks.length;
            dmaZonesCount = dmaZones.length;
            const uniqueUsers = [...new Set(leaks.map(leak => leak.reported_by))].filter(user => user);
            activeUsers = uniqueUsers.length;

        } catch (dataError) {
            console.error('Data processing error:', dataError);
            // Continue with empty data
        }

        res.render('pages/graph', {
            user: req.session.user,
            totalLeaks: totalLeaks,
            dmaZonesCount: dmaZonesCount,
            activeUsers: activeUsers,
            dmaLeakData: dmaLeakData,
            monthlyData: monthlyData
        });

    } catch (error) {
        console.error('Graph route error:', error);
        // Send page with empty data
        res.render('pages/graph', {
            user: req.session.user,
            totalLeaks: 0,
            dmaZonesCount: 0,
            activeUsers: 0,
            dmaLeakData: { labels: [], counts: [] },
            monthlyData: { months: [], counts: [] }
        });
    }
});

// Real-time NRW simulation - SIMPLIFIED
async function simulateRealTimeUpdates() {
    try {
        const zones = await DMAZone.find();
        
        // 1. Update NRW% (±2% change)
        for (const zone of zones) {
            const change = (Math.random() - 0.5) * 4;
            zone.nrw = Math.max(5, Math.min(80, zone.nrw + change));
            
            // 2. Update timestamp
            zone.updatedAt = new Date();
            await zone.save();
        }
        
        // 3. Log update
        console.log('🔄 NRW updated:', new Date().toLocaleTimeString());
    } catch (error) {
        console.error('Update error:', error);
    }
}
setInterval(simulateRealTimeUpdates, 30000);

// TEMPORARY: Clear and reset database (add this, run once, then remove)
app.get('/reset-data', async (req, res) => {
    try {
        // Delete all existing data
        await DMAZone.deleteMany({});
        await Leak.deleteMany({});

        // Add fresh data with proper zone_id
        await DMAZone.create([
            { zone_id: 'DMA_001', name: 'City Center', location: 'Downtown Area', connections: 1500, nrw: 35 },
            { zone_id: 'DMA_002', name: 'Industrial Zone', location: 'East Industrial Area', connections: 800, nrw: 25 },
            { zone_id: 'DMA_003', name: 'Residential North', location: 'North Residential', connections: 2000, nrw: 15 }
        ]);

        console.log('✅ Database reset with proper zone_ids');
        res.send('Database reset successfully!');
    } catch (error) {
        console.error('Reset error:', error);
        res.status(500).send('Reset failed');
    }
});


// Reset all users with new passwords
app.get('/fix-login', async (req, res) => {
    try {
        // Delete all existing users
        await User.deleteMany({});

        // Create new users with secure passwords
        await User.create([
            {
                username: 'admin',
                password: bcrypt.hashSync('admin2004', 10),
                role: 'dma_staff',
                name: 'System Admin'
            },
            {
                username: 'field_tech',
                password: bcrypt.hashSync('tech2004', 10),
                role: 'field_team',
                name: 'Field Technician'
            },
            {
                username: 'user',
                password: bcrypt.hashSync('user2004', 10),
                role: 'public_user',
                name: 'Public User'
            }
        ]);

        console.log('✅ All users reset with new passwords!');
        res.send(`
            <h2>✅ Login Fixed!</h2>
            <p>New passwords set. Use these credentials:</p>
            <ul>
                <li><strong>Admin:</strong> admin / admin2004</li>
                <li><strong>Field Tech:</strong> field_tech / tech2004!</li>
                <li><strong>User:</strong> user / user2004</li>
            </ul>
            <a href="/login">Go to Login</a>
        `);
    } catch (error) {
        console.error('Reset error:', error);
        res.status(500).send('Reset failed');
    }
});

// Start server
app.listen(PORT, () => {
    console.log('🎉 Jal Rakshak NRW System with AUTHENTICATION!');
    console.log('🔐 Login URLs:');
    console.log('   DMA Staff: admin / admin2004');
    console.log('   Field Team: field_tech / tech2004');
    console.log('   Public User: user / user2004');
    console.log('📊 Dashboard: http://localhost:3000/dashboard');
});