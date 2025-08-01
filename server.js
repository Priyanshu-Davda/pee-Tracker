const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const PORT = 3000;

app.use(express.static('public'));
app.use(express.json());

const db = new sqlite3.Database('database.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE
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

app.post('/join', (req, res) => {
  const { name } = req.body;
  db.run(`INSERT OR IGNORE INTO users(name) VALUES(?)`, [name], function (err) {
    if (err) return res.status(500).send('Error joining');
    res.json({ id: this.lastID });
  });
});

app.post('/pee', (req, res) => {
  const { name } = req.body;
  db.get(`SELECT id FROM users WHERE name = ?`, [name], (err, row) => {
    if (!row) return res.status(404).send('User not found');
    db.run(`INSERT INTO pee_logs(user_id) VALUES(?)`, [row.id], err => {
      if (err) return res.status(500).send('Error logging pee');
      res.sendStatus(200);
    });
  });
});

app.get('/leaderboard', (req, res) => {
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

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
