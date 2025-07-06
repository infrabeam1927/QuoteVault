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

// ------------ Routes ------------

// Home redirects to login
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Signup page
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/signup.html'));
});

// Login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

// Dashboard (protected)
app.get('/dashboard', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/dashboard.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Handle user signup
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashedPassword], function(err) {
    if (err) {
      console.error(err.message);
      return res.send('Signup failed: email might already be in use.');
    }
    req.session.userId = this.lastID;
    res.redirect('/dashboard');
  });
});

// Handle user login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) {
      return res.send('Invalid email or password.');
    }

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.userId = user.id;
      res.redirect('/dashboard');
    } else {
      res.send('Invalid email or password.');
    }
  });
});

// Add a new quote
app.post('/add-quote', requireLogin, (req, res) => {
  const userId = req.session.userId;
  const content = req.body.quote;

  db.run(`INSERT INTO quotes (user_id, content) VALUES (?, ?)`, [userId, content], (err) => {
    if (err) {
      console.error(err.message);
    }
    res.redirect('/dashboard');
  });
});

// Get all quotes for logged-in user
app.get('/quotes', requireLogin, (req, res) => {
  const userId = req.session.userId;

  db.all(`SELECT content FROM quotes WHERE user_id = ? ORDER BY created_at DESC`, [userId], (err, rows) => {
    if (err) {
      return res.json([]);
    }
    res.json(rows);
  });
});

// Middleware to protect routes
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

// Start the server
app.listen(3000, () => {
  console.log('QuoteVault is running at http://localhost:3000');
});
