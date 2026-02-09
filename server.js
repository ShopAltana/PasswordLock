// server.js
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000; // allow hosting platforms to assign their own port

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
let db;
let passwordsCollection;

async function connectDB() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db('password-system');
    passwordsCollection = db.collection('passwords');
    console.log('✓ Connected to MongoDB');

    // Create index for autimatic cleanup
    await passwordsCollection.createIndex({ expiryTime: 1 }, {expireAfterSeconds: 0 });
  }
  catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
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
  const now = Date.now();
  await passwordsCollection.deleteMany({ expiryTime: {$lt: now } });
}

// API: Generate new password
app.post('/api/generate-password', async (req, res) => {
  try {
    const password = generateAlphaNumericPassword(6);
    const expiryTime = Date.now() + (14 * 24 * 60 * 60 * 1000); // 2 weeks
    const passwordId = Date.now().toString() + Math.random().toString(36).substr(2, 9);

    await cleanupExpiredPasswords();

    const passwordData = {
      id: passwordId,
      password: password,
      expiryTime,
      createdAt: Date.now()
    };

    await passwordsCollection.insertOne(passwordData);

    const totalActivePasswords = await passwordsCollection.countDocuments();

    res.json({
      success: true,
      password,
      passwordId,
      expiryTime,
      expiryDate: new Date(expiryTime).toLocaleString(),
      totalActivePasswords
    });
  } catch (error) {
    console.error('Error generating password:', error);
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

    await cleanupExpiredPasswords();

    const totalPasswords = await passwordsCollection.countDocuments();

    if (totalPasswords === 0) {
      return res.json({ success: false, message: 'No passwords have been generated yet' });
    }

    const matchingPassword = await passwordsCollection.findOne({
      password: password
    });

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
    console.error('Error verifying password:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Check all active passwords status
app.get('/api/check-passwords', async (req, res) => {
  try {
    await cleanupExpiredPasswords();

    const passwords = await passwordsCollection.find({}).toArray();

    if (passwords.length === 0) {
      return res.json({ exists: false, count: 0 });
    }

    res.json({
      exists: true,
      count: passwords.length,
      passwords: passwords.map(p => ({
        id: p.id,
        password: p.password,
        createdAt: new Date(p.createdAt).toLocaleString(),
        expiryDate: new Date(p.expiryTime).toLocaleString(),
        daysRemaining: Math.ceil((p.expiryTime - Date.now()) / (24 * 60 * 60 * 1000))
      }))
    });
  } catch (error) {
    console.error('Error checking passwords:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Delete a specific password
app.delete('/api/delete-password/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await passwordsCollection.deleteOne({ id });

    if (result.deletedCount > 0) {
      return res.json({ success: true, message: 'Password deleted' });
    } 
    else {
      return res.json({ success: false, message: 'Password not found' });
    }
  } catch (error) {
    console.error('Error deleting password:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Delete all passwords
app.delete('/api/delete-all-passwords', async (req, res) => {
  try {
    await passwordsCollection.deleteMany({});
    res.json({ success: true, message: 'All passwords deleted' });
  } catch (error) {
    console.error('Error deleting passwords:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});



