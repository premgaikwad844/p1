const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

// NeonDB connection string (replace with your actual connection string)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'YOUR_NEONDB_CONNECTION_STRING_HERE',
  ssl: { rejectUnauthorized: false }
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));

// Render login page
app.get('/login', (req, res) => {
  res.render('login');
});

// Render registration page
app.get('/register', (req, res) => {
  res.render('register');
});

// Handle registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('Username and password are required.');
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hashedPassword]);
    res.redirect('/login');
  } catch (err) {
    if (err.code === '23505') { // unique_violation
      res.send('Username already exists.');
    } else {
      res.send('Error registering user.');
    }
  }
});

// Handle login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('Username and password are required.');
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.send('Invalid username or password.');
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (match) {
      res.send('Login successful!');
    } else {
      res.send('Invalid username or password.');
    }
  } catch (err) {
    res.send('Error logging in.');
  }
});

// Redirect root to login
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
}); 