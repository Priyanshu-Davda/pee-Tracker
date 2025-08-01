const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3'); // <-- Import better-sqlite3

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;

// Path for our persistent data
const dataDir = path.join(__dirname, '/var/data');
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


// New Registration Endpoint
app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).send('Name, email, and password are required.');
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).send('Error hashing password');

        try {
            const stmt = db.prepare(`INSERT INTO users(name, email, password) VALUES(?, ?, ?)`);
            const info = stmt.run(name, email, hash);
            req.session.userId = info.lastInsertRowid;
            res.json({ name });
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                return res.status(409).send('Email already exists.');
            }
            res.status(500).send('Error registering user.');
        }
    });
});

// New Login Endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    try {
        const stmt = db.prepare(`SELECT * FROM users WHERE email = ?`);
        const user = stmt.get(email);

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

// New Logout Endpoint
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        } else {
            res.sendStatus(200);
        }
    });
});


// Modified Pee Logging
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

// Modified Leaderboard
app.get('/leaderboard', isAuthenticated, (req, res) => {
    try {
        const stmt = db.prepare(`
            SELECT users.name, COUNT(pee_logs.id) AS count
            FROM users
            LEFT JOIN pee_logs ON users.id = pee_logs.user_id
            WHERE DATE(pee_logs.timestamp) >= DATE('now', '-7 days')
            GROUP BY users.id
            ORDER BY count DESC
        `);
        const rows = stmt.all();
        res.json(rows);
    } catch (error) {
        res.status(500).send('Error loading leaderboard');
    }
});

// Endpoint to check login status
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