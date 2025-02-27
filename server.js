const express = require('express');
const { Pool } = require('pg'); // Use 'mysql2/promise' if MySQL
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

// PostgreSQL connection (use MySQL if applicable)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // Serve static files (frontend)

// Serve index.html
app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));

// Register endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, password, email, name, address, user_type, test_mode } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password_hash, email, name, address, user_type, test_mode) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [username, hashedPassword, email, name, address, user_type || 'user', test_mode === 'true' || test_mode === true]
        );
        res.send('Registration successful');
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).send('Internal server error');
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (rows.length && await bcrypt.compare(password, rows[0].password_hash)) {
            const token = jwt.sign({ user_id: rows[0].user_id }, process.env.JWT_SECRET);
            res.json({ token, test_mode: rows[0].test_mode });
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Internal server error');
    }
});

// Profile endpoint
app.get('/users/me', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Unauthorized');
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { rows } = await pool.query('SELECT user_id, username, email, name, address, user_type, balance, test_mode FROM users WHERE user_id = $1', [decoded.user_id]);
        if (rows.length) res.json(rows[0]);
        else res.status(404).send('User not found');
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).send('Internal server error');
    }
});

// Additional endpoints (stubbed for now)
app.get('/users', async (req, res) => res.json([])); // For search, implement later
app.post('/transactions', async (req, res) => res.send('Transaction stub')); // Implement later
app.get('/transactions', async (req, res) => res.json([])); // Implement later

app.listen(process.env.PORT || 3000, () => console.log(`Server on port ${process.env.PORT || 3000}`));