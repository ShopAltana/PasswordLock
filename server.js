// server.js
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000; // allow hosting platforms to assign their own port

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Simple file-based storage (for production, use a real database like MongoDB, PostgreSQL, etc.)
const DB_FILE = path.join(__dirname, 'passwords.json');

// Initialize database file
async function initDB() {
  try {
    await fs.access(DB_FILE);
  } catch {
    await fs.writeFile(DB_FILE, JSON.stringify({ passwords: [] }));
  }
}

// Read database
async function readDB() {
  const data = await fs.readFile(DB_FILE, 'utf8');
  return JSON.parse(data);
}

// Write database
async function writeDB(data) {
  await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2));
}

// Generate alphanumeric password
function generateAlphaNumericPassword(length = 6) {
  const characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return password;
}

// Clean up expired passwords
async function cleanupExpiredPasswords() {
  const db = await readDB();
  const now = Date.now();
  db.passwords = db.passwords.filter(p => p.expiryTime > now);
  await writeDB(db);
  return db;
}

// API: Generate new password
app.post('/api/generate-password', async (req, res) => {
  try {
    const password = generateAlphaNumericPassword(6);
    const expiryTime = Date.now() + (14 * 24 * 60 * 60 * 1000); // 2 weeks
    const passwordId = Date.now().toString() + Math.random().toString(36).substr(2, 9);

    let db = await cleanupExpiredPasswords();

    const passwordData = {
      id: passwordId,
      password: password.toUpperCase(),
      expiryTime,
      createdAt: Date.now()
    };

    db.passwords.push(passwordData);
    await writeDB(db);

    res.json({
      success: true,
      password,
      passwordId,
      expiryTime,
      expiryDate: new Date(expiryTime).toLocaleString(),
      totalActivePasswords: db.passwords.length
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Verify password
app.post('/api/verify-password', async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    let db = await cleanupExpiredPasswords();

    if (db.passwords.length === 0) {
      return res.json({ success: false, message: 'No passwords have been generated yet' });
    }

    const matchingPassword = db.passwords.find(
      p => p.password === password.toUpperCase()
    );

    if (matchingPassword) {
      return res.json({
        success: true,
        message: 'Login successful!',
        passwordCreated: new Date(matchingPassword.createdAt).toLocaleString(),
        expiresOn: new Date(matchingPassword.expiryTime).toLocaleString()
      });
    } else {
      return res.json({ success: false, message: 'Invalid password. Please try again.' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Check all active passwords status
app.get('/api/check-passwords', async (req, res) => {
  try {
    let db = await cleanupExpiredPasswords();

    if (db.passwords.length === 0) {
      return res.json({ exists: false, count: 0 });
    }

    res.json({
      exists: true,
      count: db.passwords.length,
      passwords: db.passwords.map(p => ({
        id: p.id,
        password: p.password,
        createdAt: new Date(p.createdAt).toLocaleString(),
        expiryDate: new Date(p.expiryTime).toLocaleString(),
        daysRemaining: Math.ceil((p.expiryTime - Date.now()) / (24 * 60 * 60 * 1000))
      }))
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Delete a specific password
app.delete('/api/delete-password/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let db = await readDB();

    const initialCount = db.passwords.length;
    db.passwords = db.passwords.filter(p => p.id !== id);

    if (db.passwords.length < initialCount) {
      await writeDB(db);
      return res.json({ success: true, message: 'Password deleted' });
    } else {
      return res.json({ success: false, message: 'Password not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Delete all passwords
app.delete('/api/delete-all-passwords', async (req, res) => {
  try {
    const db = { passwords: [] };
    await writeDB(db);
    res.json({ success: true, message: 'All passwords deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});
