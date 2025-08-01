const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// Ensure data directory exists
const dataDir = path.join(__dirname, '/var/data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'database.db');

app.use(express.static('public'));
app.use(express.json());

// Session middleware setup
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: dataDir
    }),
    secret: 'a very secret key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

// Initialize the database with better-sqlite3
const db = new Database(dbPath, { verbose: console.log });

// Create tables if they don't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS pee_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )
`);

// Middleware to protect routes
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).send('You need to log in first.');
    }
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
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).send('Name, email, and password are required.');
    }

    // Validate name
    const nameError = validateName(name);
    if (nameError) {
        return res.status(400).send(nameError);
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).send('Please enter a valid email address.');
    }

    // Validate password strength
    if (password.length < 6) {
        return res.status(400).send('Password must be at least 6 characters long.');
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).send('Error hashing password');

        try {
            const stmt = db.prepare(`INSERT INTO users(name, email, password) VALUES(?, ?, ?)`);
            const info = stmt.run(name.trim(), email.toLowerCase().trim(), hash);
            req.session.userId = info.lastInsertRowid;
            res.json({ name: name.trim() });
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                return res.status(409).send('Email already exists.');
            }
            res.status(500).send('Error registering user.');
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
                res.json({ name: user.name });
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

// Pee Logging Endpoint
app.post('/pee', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    try {
        const stmt = db.prepare(`INSERT INTO pee_logs(user_id) VALUES(?)`);
        stmt.run(userId);
        res.sendStatus(200);
    } catch (error) {
        res.status(500).send('Error logging pee');
    }
});

// Dashboard Statistics Endpoint
app.get('/dashboard-stats', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    try {
        // Get today's count
        const todayStmt = db.prepare(`
            SELECT COUNT(*) AS count
            FROM pee_logs
            WHERE user_id = ? AND DATE(timestamp) = DATE('now')
        `);
        const todayResult = todayStmt.get(userId);

        // Get this week's count
        const weekStmt = db.prepare(`
            SELECT COUNT(*) AS count
            FROM pee_logs
            WHERE user_id = ? AND DATE(timestamp) >= DATE('now', '-7 days')
        `);
        const weekResult = weekStmt.get(userId);

        // Get last pee time
        const lastPeeStmt = db.prepare(`
            SELECT timestamp
            FROM pee_logs
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
        `);
        const lastPeeResult = lastPeeStmt.get(userId);

        res.json({
            todayCount: todayResult.count,
            weekCount: weekResult.count,
            lastPeeTime: lastPeeResult ? lastPeeResult.timestamp : null
        });
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
        res.status(500).send('Error loading dashboard statistics');
    }
});

// Leaderboard Endpoint
app.get('/leaderboard', isAuthenticated, (req, res) => {
    try {
        const stmt = db.prepare(`
            SELECT users.name, COUNT(pee_logs.id) AS count
            FROM users
            LEFT JOIN pee_logs ON users.id = pee_logs.user_id
            WHERE pee_logs.timestamp IS NULL OR DATE(pee_logs.timestamp) >= DATE('now', '-7 days')
            GROUP BY users.id, users.name
            HAVING COUNT(pee_logs.id) > 0
            ORDER BY count DESC
            LIMIT 10
        `);
        const rows = stmt.all();
        res.json(rows);
    } catch (error) {
        console.error('Error loading leaderboard:', error);
        res.status(500).send('Error loading leaderboard');
    }
});

// Check login status
app.get('/session', (req, res) => {
    if (req.session.userId) {
        try {
            const stmt = db.prepare(`SELECT name FROM users WHERE id = ?`);
            const user = stmt.get(req.session.userId);
            if (!user) {
                return res.json({ loggedIn: false });
            }
            res.json({ loggedIn: true, name: user.name });
        } catch (error) {
            res.json({ loggedIn: false });
        }
    } else {
        res.json({ loggedIn: false });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});