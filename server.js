const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { initDatabase, dbRun, dbGet, dbAll } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-rating-key';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- VALIDATION HELPERS ---
function validateName(name) {
  return typeof name === 'string' && name.trim().length >= 20 && name.trim().length <= 60;
}

function validateAddress(address) {
  return typeof address === 'string' && address.trim().length > 0 && address.trim().length <= 400;
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return typeof email === 'string' && emailRegex.test(email);
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 16) {
    return false;
  }
  const hasUppercase = /[A-Z]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  return hasUppercase && hasSpecial;
}

// --- MIDDLEWARE ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Unauthorized access for your role' });
    }
    next();
  };
}

// --- AUTHENTICATION API ---

// User Registration (Normal User)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, address, password } = req.body;

    if (!validateName(name)) {
      return res.status(400).json({ error: 'Name must be between 20 and 60 characters.' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    if (!validateAddress(address)) {
      return res.status(400).json({ error: 'Address must not exceed 400 characters.' });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({
        error: 'Password must be 8-16 characters and contain at least one uppercase letter and one special character.'
      });
    }

    const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await dbRun(
      'INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)',
      [name.trim(), email.trim(), hashedPassword, address.trim(), 'user']
    );

    res.status(201).json({ message: 'Registration successful! You can now log in.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Single Login System
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (!password) {
      return res.status(400).json({ error: 'Please enter your password.' });
    }

    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        address: user.address
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update Password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both current password and new password are required.' });
    }
    if (!validatePassword(newPassword)) {
      return res.status(400).json({
        error: 'New password must be 8-16 characters and contain at least one uppercase letter and one special character.'
      });
    }

    const user = await dbGet('SELECT password FROM users WHERE id = ?', [req.user.id]);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    await dbRun('UPDATE users SET password = ? WHERE id = ?', [newHashedPassword, req.user.id]);

    res.json({ message: 'Password updated successfully!' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// --- SYSTEM ADMINISTRATOR API ---

// Admin Add New User (Normal User or Admin)
app.post('/api/admin/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { name, email, password, address, role } = req.body;

    if (!validateName(name)) {
      return res.status(400).json({ error: 'Name must be between 20 and 60 characters.' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    if (!validateAddress(address)) {
      return res.status(400).json({ error: 'Address must not exceed 400 characters.' });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({
        error: 'Password must be 8-16 characters and contain at least one uppercase letter and one special character.'
      });
    }
    if (!role || !['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Role must be either admin or user.' });
    }

    const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already in use.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await dbRun(
      'INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)',
      [name.trim(), email.trim(), hashedPassword, address.trim(), role]
    );

    res.status(201).json({ message: `Successfully created new ${role} user.` });
  } catch (error) {
    console.error('Admin add user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin Add New Store (Creates Store + Owner User automatically)
app.post('/api/admin/stores', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { name, email, password, address } = req.body;

    if (!validateName(name)) {
      return res.status(400).json({ error: 'Store/Owner Name must be between 20 and 60 characters.' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    if (!validateAddress(address)) {
      return res.status(400).json({ error: 'Address must not exceed 400 characters.' });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({
        error: 'Owner password must be 8-16 characters and contain at least one uppercase letter and one special character.'
      });
    }

    // Verify unique email in users table first
    const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered for a store or user.' });
    }

    // Create the Store Owner user first
    const hashedPassword = await bcrypt.hash(password, 10);
    const userInsert = await dbRun(
      'INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)',
      [name.trim(), email.trim(), hashedPassword, address.trim(), 'owner']
    );

    const ownerId = userInsert.id;

    // Create the Store referencing the owner ID
    await dbRun(
      'INSERT INTO stores (name, email, address, owner_id) VALUES (?, ?, ?, ?)',
      [name.trim(), email.trim(), address.trim(), ownerId]
    );

    res.status(201).json({ message: 'Store and Store Owner successfully added.' });
  } catch (error) {
    console.error('Admin add store error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin Dashboard stats
app.get('/api/admin/dashboard', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const usersCount = await dbGet('SELECT COUNT(*) as count FROM users');
    const storesCount = await dbGet('SELECT COUNT(*) as count FROM stores');
    const ratingsCount = await dbGet('SELECT COUNT(*) as count FROM ratings');

    res.json({
      totalUsers: usersCount.count,
      totalStores: storesCount.count,
      totalRatings: ratingsCount.count
    });
  } catch (error) {
    console.error('Admin dashboard stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin view list of Normal and Admin users
app.get('/api/admin/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    // Normal and Admin users (excluding store owners in user list to make it cleaner, or list all users? 
    // Prompt says: "Can view a list of normal and admin users with: Name, Email, Address, Role." 
    // And "Can view details of all users... If the user is a Store Owner, their Rating should also be displayed."
    // So for the list, we filter where role IS NOT 'owner', or we can query users. We will match "normal and admin users".
    const users = await dbAll(`
      SELECT id, name, email, address, role, created_at 
      FROM users 
      WHERE role IN ('admin', 'user')
    `);
    res.json(users);
  } catch (error) {
    console.error('Admin list users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin view list of Stores
app.get('/api/admin/stores', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const stores = await dbAll(`
      SELECT s.id, s.name, s.email, s.address, s.owner_id, s.created_at, AVG(r.rating) as average_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      GROUP BY s.id
    `);
    res.json(stores);
  } catch (error) {
    console.error('Admin list stores error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin view user details (any user, including Store Owner with average rating)
app.get('/api/admin/users/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await dbGet('SELECT id, name, email, address, role, created_at FROM users WHERE id = ?', [userId]);

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    if (user.role === 'owner') {
      const storeRating = await dbGet(`
        SELECT AVG(r.rating) as average_rating
        FROM stores s
        LEFT JOIN ratings r ON s.id = r.store_id
        WHERE s.owner_id = ?
      `, [userId]);

      user.average_rating = storeRating.average_rating || 0;
    }

    res.json(user);
  } catch (error) {
    console.error('Admin get user details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// --- NORMAL USER API ---

// List of all registered stores with average rating & current user's submitted rating
app.get('/api/stores', authenticateToken, requireRole(['user']), async (req, res) => {
  try {
    const userId = req.user.id;
    const stores = await dbAll(`
      SELECT s.id, s.name, s.email, s.address,
             AVG(r.rating) as average_rating,
             (SELECT rating FROM ratings WHERE store_id = s.id AND user_id = ?) as user_rating
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      GROUP BY s.id
    `, [userId]);

    res.json(stores);
  } catch (error) {
    console.error('Get stores error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Submit a rating (1-5)
app.post('/api/ratings', authenticateToken, requireRole(['user']), async (req, res) => {
  try {
    const { store_id, rating } = req.body;
    const userId = req.user.id;

    if (!store_id) {
      return res.status(400).json({ error: 'Store ID is required.' });
    }
    const valRating = parseInt(rating, 10);
    if (isNaN(valRating) || valRating < 1 || valRating > 5) {
      return res.status(400).json({ error: 'Rating must be an integer between 1 and 5.' });
    }

    // Verify store exists
    const store = await dbGet('SELECT id FROM stores WHERE id = ?', [store_id]);
    if (!store) {
      return res.status(404).json({ error: 'Store not found.' });
    }

    // Verify rating hasn't been submitted yet
    const existingRating = await dbGet('SELECT id FROM ratings WHERE user_id = ? AND store_id = ?', [userId, store_id]);
    if (existingRating) {
      return res.status(400).json({ error: 'You have already rated this store. Please modify your rating instead.' });
    }

    await dbRun(
      'INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?)',
      [userId, store_id, valRating]
    );

    res.status(201).json({ message: 'Rating submitted successfully!' });
  } catch (error) {
    console.error('Submit rating error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Modify rating
app.put('/api/ratings/:storeId', authenticateToken, requireRole(['user']), async (req, res) => {
  try {
    const storeId = req.params.storeId;
    const { rating } = req.body;
    const userId = req.user.id;

    const valRating = parseInt(rating, 10);
    if (isNaN(valRating) || valRating < 1 || valRating > 5) {
      return res.status(400).json({ error: 'Rating must be an integer between 1 and 5.' });
    }

    const existingRating = await dbGet('SELECT id FROM ratings WHERE user_id = ? AND store_id = ?', [userId, storeId]);
    if (!existingRating) {
      return res.status(404).json({ error: 'No existing rating found for this store to modify.' });
    }

    await dbRun(
      'UPDATE ratings SET rating = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND store_id = ?',
      [valRating, userId, storeId]
    );

    res.json({ message: 'Rating modified successfully!' });
  } catch (error) {
    console.error('Modify rating error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// --- STORE OWNER API ---

// Store Owner Dashboard
app.get('/api/owner/dashboard', authenticateToken, requireRole(['owner']), async (req, res) => {
  try {
    const ownerId = req.user.id;

    // Get the store owned by this owner
    const store = await dbGet('SELECT id, name FROM stores WHERE owner_id = ?', [ownerId]);
    if (!store) {
      return res.status(404).json({ error: 'No store associated with this owner account.' });
    }

    // Get average rating
    const averageRatingRow = await dbGet('SELECT AVG(rating) as avg_rating FROM ratings WHERE store_id = ?', [store.id]);
    const averageRating = averageRatingRow.avg_rating || 0;

    // Get users who submitted ratings for their store
    const reviewers = await dbAll(`
      SELECT u.name, u.email, u.address, r.rating, r.updated_at
      FROM ratings r
      JOIN users u ON r.user_id = u.id
      WHERE r.store_id = ?
    `, [store.id]);

    res.json({
      storeName: store.name,
      averageRating: parseFloat(averageRating.toFixed(2)),
      reviewers
    });
  } catch (error) {
    console.error('Owner dashboard stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Fallback for SPA routing: serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start application
async function startServer() {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to initialize database and start server:', error);
    process.exit(1);
  }
}

startServer();
