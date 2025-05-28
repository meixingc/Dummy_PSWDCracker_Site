require('dotenv').config(); // load env stuff
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 4000;

// some constants (these are from tutorials i watched lol)
const SALT_ROUNDS = 10;
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const PBKDF2_ITERATIONS = 100000;

// connect to the db (this needs to match your .env file!)
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(cors());
app.use(express.json()); // allows us to read json bodies

// turns password + salt into encryption key
function getKey(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

// encrypt password stuff before saving
function encrypt(text, masterPassword) {
  const salt = crypto.randomBytes(16); // fresh salt each time!
  const saltHex = salt.toString('hex');
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = getKey(masterPassword, saltHex);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');

  return {
    encrypted,
    iv: iv.toString('hex'),
    salt: saltHex,
  };
}

// decrypt stuff using the same password + salt
function decrypt(encrypted, ivHex, masterPassword, saltHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const key = getKey(masterPassword, saltHex);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
}

// checks for jwt and adds user info to request
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1]; // i always forget the format lol

  if (!token) return res.status(401).json({ message: 'no token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (oops) {
    return res.status(403).json({ message: 'invalid token' });
  }
};

// signup endpoint (makes a new user)
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'please send both username and password' });

  try {
    const existing = await db.query('select * from users where username = $1', [username]);
    if (existing.rows.length > 0)
      return res.status(400).json({ message: 'username already taken :(' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    const result = await db.query(
      'insert into users (username, password) values ($1, $2) returning id, username',
      [username, hash]
    );

    res.status(201).json({ message: 'account created!', user: result.rows[0] });
  } catch (err) {
    console.error('signup error:', err);
    res.status(500).json({ message: 'oops, something broke on our end' });
  }
});

// login endpoint (checks password and gives token)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ message: 'need username and password pls' });

  try {
    const result = await db.query('select * from users where username = $1', [username]);
    if (result.rows.length === 0)
      return res.status(400).json({ message: 'bad username or password' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: 'bad username or password' });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'you are logged in!',
      username: user.username,
      token,
    });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ message: 'something went wrong on server' });
  }
});

// saves a password entry
app.post('/vault/add', authenticate, async (req, res) => {
  const { site, login, password, masterPassword } = req.body;

  if (!site || !login || !password || !masterPassword)
    return res.status(400).json({ message: 'missing stuff, check your fields' });

  try {
    const { encrypted, iv, salt } = encrypt(password, masterPassword);

    await db.query(
      `insert into vault (user_id, site, login, encrypted_password, iv, salt)
       values ($1, $2, $3, $4, $5, $6)`,
      [req.userId, site, login, encrypted, iv, salt]
    );

    res.status(201).json({ message: 'saved! nice job' });
  } catch (err) {
    console.error('vault add error:', err);
    res.status(500).json({ message: 'server issue while saving' });
  }
});

// gets all saved entries (but decrypted)
app.post('/vault/list', authenticate, async (req, res) => {
  const { masterPassword } = req.body;

  if (!masterPassword)
    return res.status(400).json({ message: 'please enter your master password' });

  try {
    const result = await db.query('select * from vault where user_id = $1', [req.userId]);

    const passwords = result.rows.map((entry) => {
      try {
        const realPw = decrypt(
          entry.encrypted_password,
          entry.iv,
          masterPassword,
          entry.salt
        );

        return {
          site: entry.site,
          login: entry.login,
          password: realPw,
        };
      } catch {
        // couldn't decrypt, probably wrong master password
        return {
          site: entry.site,
          login: entry.login,
          password: '****',
        };
      }
    });

    res.json(passwords);
  } catch (err) {
    console.error('vault list error:', err);
    res.status(500).json({ message: 'could not fetch entries' });
  }
});

// start the server (woohoo!)
app.listen(port, () => {
  console.log(`server is live on port ${port} ✨`);
});
