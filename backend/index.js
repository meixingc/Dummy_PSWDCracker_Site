require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 4000;
const SALT_ROUNDS = 10;
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const PBKDF2_ITERATIONS = 100000;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(cors());
app.use(express.json());

// get encryption key from master password and salt
function getKey(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

// encrypt using AES-256 with a random salt per entry
function encrypt(text, masterPassword) {
  const salt = crypto.randomBytes(16); 
  const saltHex = salt.toString('hex');
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = getKey(masterPassword, saltHex);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
  return { encrypted, iv: iv.toString('hex'), salt: saltHex };
}

// decrypt using AES-256 and salt
function decrypt(encrypted, ivHex, masterPassword, saltHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const key = getKey(masterPassword, saltHex);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
}

// JWT Authentication middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Signup route — bcrypt hashing, no salt column needed here
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Missing username or password' });

  try {
    const existing = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0)
      return res.status(400).json({ message: 'User already exists' });

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

// login - bcrypt compare, no salt!!!
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Missing username or password' });

  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0)
      return res.status(400).json({ message: 'Invalid username or password' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: 'Invalid username or password' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', username: user.username, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// save vault entry — storing salt, iv, encrypted_password
app.post('/vault/add', authenticate, async (req, res) => {
  const { site, login, password, masterPassword } = req.body;
  if (!site || !login || !password || !masterPassword)
    return res.status(400).json({ message: 'Missing fields' });

  try {
    const { encrypted, iv, salt } = encrypt(password, masterPassword);

    await db.query(
      `INSERT INTO vault (user_id, site, login, encrypted_password, iv, salt) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [req.userId, site, login, encrypted, iv, salt]
    );

    res.status(201).json({ message: 'Password stored securely' });
  } catch (err) {
    console.error('Add vault error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// list vault entries — decrypt with masterPassword and salt
app.post('/vault/list', authenticate, async (req, res) => {
  const { masterPassword } = req.body;
  if (!masterPassword)
    return res.status(400).json({ message: 'Missing master password' });

  try {
    const result = await db.query('SELECT * FROM vault WHERE user_id = $1', [req.userId]);

    const passwords = result.rows.map(entry => {
      try {
        const decryptedPassword = decrypt(
          entry.encrypted_password,
          entry.iv,
          masterPassword,
          entry.salt
        );
        return {
          site: entry.site,
          login: entry.login,
          password: decryptedPassword,
        };
      } catch {
        return {
          site: entry.site,
          login: entry.login,
          password: '****', // placeholder if decryption fails (wrong password)
        };
      }
    });

    res.json(passwords);
  } catch (err) {
    console.error('List vault error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}! :3`);
});
