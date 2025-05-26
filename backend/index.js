require('dotenv').config(); // must be first
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 4000;
const SALT_ROUNDS = 10;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(cors());
app.use(express.json());

// JWT auth middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Sign up route
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  console.log('Signup attempt:', username);

  if (!username || !password) {
    return res.status(400).json({ message: 'Missing username or password' });
  }

  try {
    const existingUser = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await db.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hash]
    );

    res.status(201).json({ message: 'User created', user: result.rows[0] });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt for:', username);

  if (!username || !password) {
    return res.status(400).json({ message: 'Missing username or password' });
  }

  try {
    const userResult = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const user = userResult.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful', username: user.username, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create password entry
app.post('/passwords', authenticate, async (req, res) => {
  const { account, username, password } = req.body;
  if (!account || !username || !password) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  try {
    await db.query(
      'INSERT INTO passwords (user_id, account, username, password) VALUES ($1, $2, $3, $4)',
      [req.userId, account, username, password]
    );
    res.status(201).json({ message: 'Password saved' });
  } catch (err) {
    console.error('Save password error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get password entries
app.get('/passwords', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, account, username, password FROM passwords WHERE user_id = $1',
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch passwords error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
