const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator'); // Import express-validator
const db = require('../db'); 
const router = express.Router();

// Login route
router.post(
    '/login',
    [
        // Input Validation for login
        body('username').trim().notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required'),
    ],
    (req, res) => {
        // Handle validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() }); // Return validation errors
        }

        const { username, password } = req.body;

        const query = 'SELECT * FROM users WHERE username = ?';
        db.query(query, [username], (err, results) => {
            if (err) return res.status(500).send('Server error');
            if (results.length === 0) return res.status(404).send('User not found');

            const user = results[0];
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) return res.status(500).send('Error validating password');
                if (!isMatch) return res.status(401).send('Invalid credentials');

                req.session.userId = user.id;
                res.send('Login successful');
            });
        });
    }
);

// Register route
router.post(
    '/register',
    [
        // Input Validation for registration
        body('username')
            .trim()
            .isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters')
            .isAlphanumeric().withMessage('Username must contain only letters and numbers'),
        body('password')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
            .matches(/[0-9]/).withMessage('Password must contain at least one number')
            .matches(/[\W]/).withMessage('Password must contain at least one special character'),
    ],
    async (req, res) => {
        // Handle validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() }); // Return validation errors
        }

        const { username, password } = req.body;

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            const query = 'INSERT INTO users (username, password) VALUES (?, ?)';

            db.query(query, [username, hashedPassword], (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(409).send('Username already exists');
                    }
                    return res.status(500).send('Server error');
                }
                res.send('Registration successful');
            });
        } catch (error) {
            res.status(500).send('Error encrypting password');
        }
    }
);

module.exports = router;
