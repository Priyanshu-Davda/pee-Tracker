const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// Use persistent data directory - will survive deployments
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'pee_tracker.db');
const sessionsPath = path.join(dataDir, 'sessions.db');

app.use(express.static('public'));
app.use(express.json());

// Session middleware setup
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: dataDir
    }),
    secret: process.env.SESSION_SECRET || 'pee-tracker-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
    }
}));

// Initialize the database with better-sqlite3
const db = new Database(dbPath);

// Create tables if they don't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    invite_code TEXT UNIQUE NOT NULL,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    user_id INTEGER,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(group_id) REFERENCES groups(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(group_id, user_id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS pee_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    group_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(group_id) REFERENCES groups(id)
  )
`);

// Create default admin user if none exists
const adminExists = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = TRUE').get();
if (adminExists.count === 0) {
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const hashedPassword = bcrypt.hashSync(adminPassword, saltRounds);
    db.prepare(`
        INSERT INTO users (email, password, name, is_admin) 
        VALUES (?, ?, ?, TRUE)
    `).run('admin@peetracker.com', hashedPassword, 'Administrator');
    console.log('Default admin created: admin@peetracker.com / admin123');
}

// Middleware to protect routes
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).send('You need to log in first.');
    }
}

function isAdmin(req, res, next) {
    if (req.session.userId) {
        const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.userId);
        if (user && user.is_admin) {
            next();
        } else {
            res.status(403).send('Admin access required.');
        }
    } else {
        res.status(401).send('You need to log in first.');
    }
}

// Helper function to generate invite code
function generateInviteCode() {
    return crypto.randomBytes(4).toString('hex').toUpperCase();
}

// Helper function to validate name
function validateName(name) {
    if (!name || name.length < 2) {
        return 'Name must be at least 2 characters long';
    }
    if (!/^[a-zA-Z\s'-]+$/.test(name)) {
        return 'Name can only contain letters, spaces, hyphens, and apostrophes';
    }
    if (name.trim() !== name) {
        return 'Name cannot start or end with spaces';
    }
    return null;
}

// Registration Endpoint
app.post('/register', (req, res) => {
    const { name, email, password, inviteCode } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).send('Name, email, and password are required.');
    }

    const nameError = validateName(name);
    if (nameError) {
        return res.status(400).send(nameError);
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).send('Please enter a valid email address.');
    }

    if (password.length < 6) {
        return res.status(400).send('Password must be at least 6 characters long.');
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).send('Error hashing password');

        const dbTransaction = db.transaction(() => {
            try {
                const stmt = db.prepare(`INSERT INTO users(name, email, password) VALUES(?, ?, ?)`);
                const result = stmt.run(name.trim(), email.toLowerCase().trim(), hash);
                const userId = result.lastInsertRowid;
                
                req.session.userId = userId;

                // If invite code provided, join that group
                if (inviteCode) {
                    const group = db.prepare('SELECT id FROM groups WHERE invite_code = ?').get(inviteCode.toUpperCase());
                    if (group) {
                        db.prepare('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)').run(group.id, userId);
                    }
                }

                res.json({ name: name.trim() });
            } catch (error) {
                if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                    throw new Error('Email already exists.');
                }
                throw new Error('Error registering user.');
            }
        });

        try {
            dbTransaction();
        } catch (error) {
            res.status(error.message === 'Email already exists.' ? 409 : 500).send(error.message);
        }
    });
});

// Login Endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).send('Email and password are required.');
    }

    try {
        const stmt = db.prepare(`SELECT * FROM users WHERE email = ?`);
        const user = stmt.get(email.toLowerCase().trim());

        if (!user) {
            return res.status(404).send('User not found.');
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.userId = user.id;
                res.json({ name: user.name, isAdmin: user.is_admin });
            } else {
                res.status(401).send('Invalid password.');
            }
        });
    } catch (error) {
        res.status(500).send('Error logging in.');
    }
});

// Logout Endpoint
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        } else {
            res.sendStatus(200);
        }
    });
});

// Create Group Endpoint
app.post('/create-group', isAuthenticated, (req, res) => {
    const { name, description } = req.body;
    const userId = req.session.userId;

    if (!name || name.trim().length < 3) {
        return res.status(400).send('Group name must be at least 3 characters long.');
    }

    try {
        const inviteCode = generateInviteCode();
        const stmt = db.prepare(`
            INSERT INTO groups (name, description, invite_code, created_by) 
            VALUES (?, ?, ?, ?)
        `);
        const result = stmt.run(name.trim(), description || '', inviteCode, userId);
        
        // Add creator to group
        db.prepare('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)').run(result.lastInsertRowid, userId);
        
        res.json({ 
            groupId: result.lastInsertRowid, 
            inviteCode,
            message: 'Group created successfully!' 
        });
    } catch (error) {
        res.status(500).send('Error creating group.');
    }
});

// Join Group Endpoint
app.post('/join-group', isAuthenticated, (req, res) => {
    const { inviteCode } = req.body;
    const userId = req.session.userId;

    if (!inviteCode) {
        return res.status(400).send('Invite code is required.');
    }

    try {
        const group = db.prepare('SELECT * FROM groups WHERE invite_code = ?').get(inviteCode.toUpperCase());
        
        if (!group) {
            return res.status(404).send('Invalid invite code.');
        }

        // Check if already a member
        const existing = db.prepare('SELECT id FROM group_members WHERE group_id = ? AND user_id = ?').get(group.id, userId);
        if (existing) {
            return res.status(409).send('You are already a member of this group.');
        }

        db.prepare('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)').run(group.id, userId);
        res.json({ message: `Successfully joined ${group.name}!` });
    } catch (error) {
        res.status(500).send('Error joining group.');
    }
});

// Get User's Groups
app.get('/my-groups', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    
    try {
        const stmt = db.prepare(`
            SELECT g.*, gm.joined_at,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = ?
            ORDER BY gm.joined_at DESC
        `);
        const groups = stmt.all(userId);
        res.json(groups);
    } catch (error) {
        res.status(500).send('Error loading groups.');
    }
});

// Pee Logging Endpoint
app.post('/pee', isAuthenticated, (req, res) => {
    const { groupId } = req.body;
    const userId = req.session.userId;
    
    try {
        let finalGroupId = groupId;
        
        // If no group specified, use user's first group
        if (!finalGroupId) {
            const userGroup = db.prepare(`
                SELECT g.id FROM groups g
                JOIN group_members gm ON g.id = gm.group_id
                WHERE gm.user_id = ?
                ORDER BY gm.joined_at ASC
                LIMIT 1
            `).get(userId);
            
            if (userGroup) {
                finalGroupId = userGroup.id;
            }
        }

        const stmt = db.prepare(`INSERT INTO pee_logs(user_id, group_id) VALUES(?, ?)`);
        stmt.run(userId, finalGroupId);
        res.sendStatus(200);
    } catch (error) {
        res.status(500).send('Error logging pee');
    }
});

// Dashboard Statistics Endpoint
app.get('/dashboard-stats', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    const { groupId } = req.query;
    
    try {
        let groupFilter = '';
        let params = [userId];
        
        if (groupId) {
            groupFilter = 'AND group_id = ?';
            params.push(groupId);
        }

        const todayStmt = db.prepare(`
            SELECT COUNT(*) AS count
            FROM pee_logs
            WHERE user_id = ? ${groupFilter} AND DATE(timestamp) = DATE('now')
        `);
        const todayResult = todayStmt.get(...params);

        const weekStmt = db.prepare(`
            SELECT COUNT(*) AS count
            FROM pee_logs
            WHERE user_id = ? ${groupFilter} AND DATE(timestamp) >= DATE('now', '-7 days')
        `);
        const weekResult = weekStmt.get(...params);

        const lastPeeStmt = db.prepare(`
            SELECT timestamp
            FROM pee_logs
            WHERE user_id = ? ${groupFilter}
            ORDER BY timestamp DESC
            LIMIT 1
        `);
        const lastPeeResult = lastPeeStmt.get(...params);

        res.json({
            todayCount: todayResult.count,
            weekCount: weekResult.count,
            lastPeeTime: lastPeeResult ? lastPeeResult.timestamp : null
        });
    } catch (error) {
        res.status(500).send('Error loading dashboard statistics');
    }
});

// Group Leaderboard Endpoint
app.get('/leaderboard', isAuthenticated, (req, res) => {
    const { groupId } = req.query;
    const userId = req.session.userId;
    
    try {
        let query = `
            SELECT u.name, COUNT(p.id) AS count, u.id as user_id
            FROM users u
            LEFT JOIN pee_logs p ON u.id = p.user_id 
                AND DATE(p.timestamp) >= DATE('now', '-7 days')
        `;
        
        let params = [];
        
        if (groupId) {
            query += ` 
                JOIN group_members gm ON u.id = gm.user_id
                WHERE gm.group_id = ? AND (p.group_id = ? OR p.group_id IS NULL)
            `;
            params = [groupId, groupId];
        } else {
            // Show leaderboard for user's groups
            query += `
                JOIN group_members gm ON u.id = gm.user_id
                JOIN group_members ugm ON gm.group_id = ugm.group_id
                WHERE ugm.user_id = ?
            `;
            params = [userId];
        }
        
        query += `
            GROUP BY u.id, u.name
            HAVING COUNT(p.id) > 0
            ORDER BY count DESC
            LIMIT 10
        `;

        const stmt = db.prepare(query);
        const rows = stmt.all(...params);
        res.json(rows);
    } catch (error) {
        res.status(500).send('Error loading leaderboard');
    }
});

// Admin Panel Endpoints
app.get('/admin/stats', isAdmin, (req, res) => {
    try {
        const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
        const totalGroups = db.prepare('SELECT COUNT(*) as count FROM groups').get().count;
        const totalPees = db.prepare('SELECT COUNT(*) as count FROM pee_logs').get().count;
        const todayPees = db.prepare('SELECT COUNT(*) as count FROM pee_logs WHERE DATE(timestamp) = DATE("now")').get().count;
        
        const recentUsers = db.prepare(`
            SELECT name, email, created_at FROM users 
            ORDER BY created_at DESC LIMIT 10
        `).all();
        
        const activeGroups = db.prepare(`
            SELECT g.name, g.invite_code, 
                   COUNT(gm.user_id) as member_count,
                   COUNT(p.id) as pee_count
            FROM groups g
            LEFT JOIN group_members gm ON g.id = gm.group_id
            LEFT JOIN pee_logs p ON g.id = p.group_id AND DATE(p.timestamp) >= DATE('now', '-7 days')
            GROUP BY g.id
            ORDER BY pee_count DESC
            LIMIT 10
        `).all();

        res.json({
            totalUsers,
            totalGroups,
            totalPees,
            todayPees,
            recentUsers,
            activeGroups
        });
    } catch (error) {
        res.status(500).send('Error loading admin stats');
    }
});

// Check login status
app.get('/session', (req, res) => {
    if (req.session.userId) {
        try {
            const stmt = db.prepare(`SELECT name, is_admin FROM users WHERE id = ?`);
            const user = stmt.get(req.session.userId);
            if (!user) {
                return res.json({ loggedIn: false });
            }
            res.json({ 
                loggedIn: true, 
                name: user.name,
                isAdmin: user.is_admin 
            });
        } catch (error) {
            res.json({ loggedIn: false });
        }
    } else {
        res.json({ loggedIn: false });
    }
});

// Serve admin panel
app.get('/admin', isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('Closing database connection...');
    db.close();
    process.exit(0);
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Admin panel available at http://localhost:${PORT}/admin`);
});