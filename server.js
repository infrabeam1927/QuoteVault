const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./users.db');

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true
}));

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
)`);

// Create quotes table
db.run(`CREATE TABLE IF NOT EXISTS quotes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Middleware to protect routes
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// Routes
app.get('/', (req, res) => res.redirect('/login'));

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashedPassword], function (err) {
    if (err) {
      return res.send('Signup failed. Try a different email.');
    }
    req.session.userId = this.lastID;
    res.redirect('/dashboard');
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (!user || err) return res.send('Invalid email or password');

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.userId = user.id;
      res.redirect('/dashboard');
    } else {
      res.send('Invalid email or password');
    }
  });
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/dashboard.html'));
});

app.post('/add-quote', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const content = req.body.quote;

  db.run(`INSERT INTO quotes (user_id, content) VALUES (?, ?)`, [userId, content], (err) => {
    res.redirect('/dashboard');
  });
});

app.post('/delete-quote', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const quoteId = req.body.id;

  db.run(`DELETE FROM quotes WHERE id = ? AND user_id = ?`, [quoteId, userId], (err) => {
    res.redirect('/dashboard');
  });
});

app.get('/quotes', requireLogin, (req, res) => {
  const userId = req.session.userId;

  db.all(`SELECT id, content FROM quotes WHERE user_id = ? ORDER BY created_at DESC`, [userId], (err, rows) => {
    res.json(rows || []);
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.listen(3000, () => {
  console.log('QuoteVault running at http://localhost:3000');
});
