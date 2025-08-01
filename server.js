const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path =require('path'); // <-- Add this line
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = process.env.PORT || 3000; // <-- Change this line
const saltRounds = 10;

// Path for our persistent data
const dataDir = path.join(__dirname, '/var/data'); // <-- Add this line
const dbPath = path.join(dataDir, 'database.db'); // <-- Add this line
const sessionDbPath = path.join(dataDir, 'sessions.db'); // <-- Add this line

app.use(express.static('public'));
app.use(express.json());

// Session middleware setup - UPDATED
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: dataDir // <-- Change this line to use the persistent directory
    }),
    secret: 'a very secret key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));

const db = new sqlite3.Database(dbPath); // <-- Change this line

// Updated Database Schema
db.serialize(() => {
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT,
      name TEXT
    )
  `);
    db.run(`
    CREATE TABLE IF NOT EXISTS pee_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

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
    const {
        name,
        email,
        password
    } = req.body;
    if (!name || !email || !password) {
        return res.status(400).send('Name, email, and password are required.');
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) return res.status(500).send('Error hashing password');

        db.run(`INSERT INTO users(name, email, password) VALUES(?, ?, ?)`, [name, email, hash], function (err) {
            if (err) {
                // 'UNIQUE constraint failed' error code for sqlite
                if (err.errno === 19) {
                    return res.status(409).send('Email already exists.');
                }
                return res.status(500).send('Error registering user.');
            }
            req.session.userId = this.lastID; // Log in the user after registration
            res.json({
                name
            });
        });
    });
});

// New Login Endpoint
app.post('/login', (req, res) => {
    const {
        email,
        password
    } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err || !user) return res.status(404).send('User not found.');

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.userId = user.id;
                res.json({
                    name: user.name
                });
            } else {
                res.status(401).send('Invalid password.');
            }
        });
    });
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


// Modified Pee Logging - now protected
app.post('/pee', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    db.run(`INSERT INTO pee_logs(user_id) VALUES(?)`, [userId], err => {
        if (err) return res.status(500).send('Error logging pee');
        res.sendStatus(200);
    });
});

// Modified Leaderboard - now protected
app.get('/leaderboard', isAuthenticated, (req, res) => {
    db.all(`
    SELECT users.name, COUNT(pee_logs.id) AS count
    FROM users
    LEFT JOIN pee_logs ON users.id = pee_logs.user_id
    WHERE DATE(pee_logs.timestamp) >= DATE('now', '-7 days')
    GROUP BY users.id
    ORDER BY count DESC
  `, (err, rows) => {
        if (err) return res.status(500).send('Error loading leaderboard');
        res.json(rows);
    });
});

// Endpoint to check login status
app.get('/session', (req, res) => {
    if (req.session.userId) {
        db.get(`SELECT name FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
            if (err || !user) {
                return res.status(404).json({
                    loggedIn: false
                });
            }
            res.json({
                loggedIn: true,
                name: user.name
            });
        });
    } else {
        res.json({
            loggedIn: false
        });
    }
});


app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});