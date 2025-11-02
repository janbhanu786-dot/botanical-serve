// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.sqlite');
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_for_prod';
const SALT_ROUNDS = 10;

// Ensure DB exists
const dbExists = fs.existsSync(DB_FILE);
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  if (!dbExists) {
    db.run(`CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    console.log('Database and users table created.');
  }
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  // Simple logging
  console.log(`${req.method} ${req.url}`);
  next();
});

// Helpers
function parseIdentifier(raw){
  if(!raw) return {type:'invalid'};
  const s = raw.trim();
  const isEmail = /\S+@\S+\.\S+/.test(s);
  const digits = s.replace(/\D/g,'');
  const isPhone = digits.length >= 6 && digits.length <= 15;
  if(isEmail) return {type:'email', value:s.toLowerCase()};
  if(isPhone) return {type:'phone', value:digits};
  return {type:'invalid'};
}

function generateToken(payload){
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authenticateToken(req, res, next){
  const auth = req.headers['authorization'];
  if(!auth) return res.status(401).json({ error: 'No token provided' });
  const parts = auth.split(' ');
  if(parts.length !== 2) return res.status(401).json({ error: 'Token malformed' });
  const token = parts[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if(err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Routes
app.post('/api/signup', async (req, res) => {
  const { name, identifier, password } = req.body;
  if(!name || !identifier || !password) return res.status(400).json({ error: 'Missing fields' });
  const id = parseIdentifier(identifier);
  if(id.type === 'invalid') return res.status(400).json({ error: 'Identifier must be a valid email or phone number' });
  if(password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const column = id.type === 'email' ? 'email' : 'phone';
  db.get(`SELECT * FROM users WHERE ${column} = ?`, [id.value], async (err, row) => {
    if(err) return res.status(500).json({ error: 'Database error' });
    if(row) return res.status(400).json({ error: 'Account with that identifier already exists' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run(`INSERT INTO users (name, email, phone, password_hash) VALUES (?,?,?,?)`, 
      [
        name,
        id.type === 'email' ? id.value : null,
        id.type === 'phone' ? id.value : null,
        hash
      ],
      function(err2) {
        if(err2) return res.status(500).json({ error: 'Could not create user' });
        const user = { id: this.lastID, name, email: id.type === 'email' ? id.value : null, phone: id.type === 'phone' ? id.value : null };
        const token = generateToken(user);
        res.json({ token, user });
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body;
  if(!identifier || !password) return res.status(400).json({ error: 'Missing fields' });
  const id = parseIdentifier(identifier);
  if(id.type === 'invalid') return res.status(400).json({ error: 'Identifier must be a valid email or phone number' });

  const column = id.type === 'email' ? 'email' : 'phone';
  db.get(`SELECT * FROM users WHERE ${column} = ?`, [id.value], async (err, row) => {
    if(err) return res.status(500).json({ error: 'Database error' });
    if(!row) return res.status(401).json({ error: 'No matching account' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({ error: 'Incorrect password' });

    const user = { id: row.id, name: row.name, email: row.email, phone: row.phone };
    const token = generateToken(user);
    res.json({ token, user });
  });
});

app.get('/api/me', authenticateToken, (req, res) => {
  // Return user info from token (no DB hit necessary)
  res.json({ user: req.user });
});

// fallback: serve index
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
