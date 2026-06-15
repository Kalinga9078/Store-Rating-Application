const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error connecting to SQLite database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
  }
});

// Promisify database methods for cleaner async/await usage
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) {
        reject(err);
      } else {
        resolve({ id: this.lastID, changes: this.changes });
      }
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
};

const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
};

// Initialize database schema
async function initDatabase() {
  // Enable foreign keys
  await dbRun('PRAGMA foreign_keys = ON;');

  // Create Users Table
  // Name validation: Min 20, Max 60
  // Address validation: Max 400
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      address TEXT NOT NULL,
      role TEXT CHECK(role IN ('admin', 'user', 'owner')) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create Stores Table
  // Owner_id points to the user record for the store owner (role = 'owner')
  await dbRun(`
    CREATE TABLE IF NOT EXISTS stores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      address TEXT NOT NULL,
      owner_id INTEGER UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create Ratings Table
  // Constraint: User can submit only 1 rating per store
  await dbRun(`
    CREATE TABLE IF NOT EXISTS ratings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      store_id INTEGER NOT NULL,
      rating INTEGER CHECK(rating BETWEEN 1 AND 5) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE CASCADE,
      UNIQUE(user_id, store_id)
    )
  `);

  // Seed default system administrator if not already exists
  const adminEmail = 'admin@starrater.com';
  const existingAdmin = await dbGet('SELECT * FROM users WHERE email = ?', [adminEmail]);

  if (!existingAdmin) {
    // Password must be 8-16 chars, contain 1 uppercase, 1 special character: "Admin123!"
    const hashedPassword = await bcrypt.hash('Admin123!', 10);
    // Name must be between 20 and 60 chars: "System Administrator User" (25 chars)
    const adminName = 'System Administrator User';
    const adminAddress = '100 Admin HQ Blvd, Tech City, Suite 404';

    await dbRun(`
      INSERT INTO users (name, email, password, address, role)
      VALUES (?, ?, ?, ?, 'admin')
    `, [adminName, adminEmail, hashedPassword, adminAddress]);

    console.log('Seeded default administrator account.');
  }
}

module.exports = {
  db,
  dbRun,
  dbGet,
  dbAll,
  initDatabase
};
