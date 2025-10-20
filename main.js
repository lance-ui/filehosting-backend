import express from 'express';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'your-secret-key';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./lance-cdn.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    api_key TEXT UNIQUE
  )`);
});

const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    cb(null, true);
  }
});

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const verifyApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API key required' });

  db.get('SELECT id, username FROM users WHERE api_key = ?', [apiKey], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid API key' });
    req.user = user;
    next();
  });
};

const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each API key to 100 requests per `windowMs`
  message: 'Too many upload requests from this API Key, please try again after 15 minutes',
  keyGenerator: (req, res) => {
    return req.user && req.user.id ? `upload_user_${req.user.id}` : req.ip; 
  },
  statusCode: 429, 
  standardHeaders: true, 
  legacyHeaders: false, 
});

app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const apiKey = crypto.randomBytes(32).toString('hex');

  db.run('INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)', [username, hashedPassword, apiKey], function(err) {
    if (err) return res.status(400).json({ error: 'Username already exists' });

    db.run(`CREATE TABLE IF NOT EXISTS files_user_${this.lastID} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT,
      hash TEXT UNIQUE,
      content TEXT,
      size INTEGER,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET);
    res.json({ message: 'User created', api_key: apiKey, token });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token, api_key: user.api_key });
  });
});

app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const userId = req.user.id;
  const hash = crypto.randomBytes(16).toString('hex');
  const content = req.file.buffer.toString('base64');

  db.run(`CREATE TABLE IF NOT EXISTS files_user_${userId} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    hash TEXT UNIQUE,
    content TEXT,
    size INTEGER,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`INSERT INTO files_user_${userId} (filename, hash, content, size) VALUES (?, ?, ?, ?)`,
    [req.file.originalname, hash, content, req.file.size], function(err) {
      if (err) return res.status(500).json({ error: 'Upload failed' });
      res.json({ message: 'File uploaded', hash });
    });
});

// Endpoint for API Key upload
app.post('/api/upload-api', verifyApiKey, apiRateLimiter, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const userId = req.user.id;
  const hash = crypto.randomBytes(16).toString('hex');
  const content = req.file.buffer.toString('base64');

  db.run(`CREATE TABLE IF NOT EXISTS files_user_${userId} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    hash TEXT UNIQUE,
    content TEXT,
    size INTEGER,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`INSERT INTO files_user_${userId} (filename, hash, content, size) VALUES (?, ?, ?, ?)`,
    [req.file.originalname, hash, content, req.file.size], function(err) {
      if (err) return res.status(500).json({ error: 'Upload failed' });
      res.json({ message: 'File uploaded', hash });
    });
});

app.get('/api/files', verifyToken, (req, res) => {
  const userId = req.user.id;
  db.all(`SELECT * FROM files_user_${userId}`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch files' });
    res.json(rows);
  });
});

// New Endpoint to get files using API Key
app.get('/api/files-api', verifyApiKey, (req, res) => {
  const userId = req.user.id;
  // Select only the required fields: id, filename, hash
  db.all(`SELECT id, filename, hash FROM files_user_${userId}`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch files' });
    res.json(rows);
  });
});

app.put('/api/files/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { newName } = req.body;
  const userId = req.user.id;

  if (!newName) return res.status(400).json({ error: 'New name required' });

  db.run(`UPDATE files_user_${userId} SET filename = ? WHERE id = ?`, [newName, id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to rename file' });
    if (this.changes === 0) return res.status(404).json({ error: 'File not found' });
    res.json({ message: 'File renamed' });
  });
});

app.delete('/api/files/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  db.run(`DELETE FROM files_user_${userId} WHERE id = ?`, [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete file' });
    if (this.changes === 0) return res.status(404).json({ error: 'File not found' });
    res.json({ message: 'File deleted' });
  });
});

app.put('/api/files/:id/content', verifyToken, (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  const userId = req.user.id;

  if (content === undefined) return res.status(400).json({ error: 'Content required' });

  const contentBase64 = Buffer.from(content).toString('base64');

  db.run(`UPDATE files_user_${userId} SET content = ? WHERE id = ?`, [contentBase64, id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update file content' });
    if (this.changes === 0) return res.status(404).json({ error: 'File not found' });
    res.json({ message: 'File content updated' });
  });
});

app.get('/download/:hash', (req, res) => {
  const hash = req.params.hash;
  // Find file by hash across all user tables
  db.all("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'files_user_%'", [], (err, tables) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    let checked = 0;
    const total = tables.length;
    let found = false;

    if (total === 0) return res.status(404).json({ error: 'File not found' });

    tables.forEach(table => {
      db.get(`SELECT * FROM ${table.name} WHERE hash = ?`, [hash], (err, file) => {
        checked++;
        if (err) {
          console.error(err);
        } else if (file && !found) {
          found = true;
          const buffer = Buffer.from(file.content, 'base64');
          res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
          res.setHeader('Content-Type', 'application/octet-stream');
          res.send(buffer);
        }
        if (checked === total && !found) {
          res.status(404).json({ error: 'File not found' });
        }
      });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
