const mysql = require('mysql');
require('dotenv').config(); // Secure Storage of Program Secrets: Load secrets from .env file

// Secure Storage of Program Secrets: Use environment variables for sensitive information
const db = mysql.createConnection({
    host: process.env.DB_HOST,     // Database host stored in .env
    user: process.env.DB_USER,     // Database user stored in .env
    password: process.env.DB_PASSWORD, // Database password stored in .env
    database: process.env.DB_NAME,  // Database name stored in .env
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('Connected to MySQL');
    }
});

module.exports = db;
