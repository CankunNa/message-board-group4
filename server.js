const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); // Authentication - Token-Based Authentication: Import JWT library
const session = require('express-session');
const helmet = require('helmet');
const xssClean = require('xss-clean'); // Anti-XSS: Import xss-clean middleware
const cookieParser = require('cookie-parser'); // Required for CSRF
const csurf = require('csurf'); // Anti-CSRF: Import csurf middleware
const { body, validationResult } = require('express-validator'); // Import express-validator
const authRoutes = require('./routes/auth'); 
const crypto = require('crypto'); // Software Signing and Verification: Import crypto library
const messageRoutes = require('./routes/messages'); // Import message routes
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Anti-XSS: Add security headers to protect against XSS attacks
app.use(helmet()); 

// Anti-XSS: Sanitize user input to prevent malicious scripts
app.use(xssClean());

// Anti-CSRF: Enable cookie parser middleware for CSRF protection
app.use(cookieParser());

// Anti-CSRF: Enable CSRF protection for all routes
const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

// Authentication - Token-Based Authentication: Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).send('Access token is required');

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Invalid or expired token');
        req.user = user; // Attach the decoded user information to the request
        next();
    });
};

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('Connected to MySQL');
    }
});

// Routes

// Static file serving
app.use(express.static('public'));

// CSRF token route
// Anti-CSRF: Provide CSRF token to the client for protected requests
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Auth routes
app.use('/auth', authRoutes);

// Use message routes (add this line after other route declarations)
app.use('/messages', messageRoutes);

// Software Signing and Verification: Generate digital signature for JSON data
function signData(data) {
    const sign = crypto.createSign('SHA256');
    sign.update(JSON.stringify(data));
    return sign.sign(process.env.PRIVATE_KEY, 'base64');
}

// Software Signing and Verification: Verify digital signature for JSON data
function verifySignature(data, signature) {
    const verify = crypto.createVerify('SHA256');
    verify.update(JSON.stringify(data));
    return verify.verify(process.env.PUBLIC_KEY, signature, 'base64');
}

// Authentication – SFA and Token-Based Authentication: Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Anti-SQL Injection: Use parameterized query to securely fetch user data
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('User not found');

        const user = results[0];

        // Password Storage: Compare the input password with the stored hashed password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Error validating password');
            if (!isMatch) return res.status(401).send('Invalid credentials');

            // MFA: Check if MFA is enabled
            if (user.mfa_enabled) {
                req.session.tempUserId = user.id; // Temporarily store user ID
                return res.status(200).send('MFA required'); // Prompt for MFA
            }

            // Authentication - Token-Based Authentication: Generate a JWT token
            const token = jwt.sign(
                { id: user.id, username: user.username },
                process.env.JWT_SECRET,
                { expiresIn: '1h' } // Token expiration time
            );

            // Software Signing and Verification: Sign the response data
            const responseData = { message: 'Login successful', token };
            const signature = signData(responseData);
            res.json({ ...responseData, signature });
        });
    });
});

// Authentication – MFA: Verify MFA route
app.post('/verify-mfa', (req, res) => {
    const { token } = req.body;

    // MFA: Verify TOTP token
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [req.session.tempUserId], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('User not found');

        const user = results[0];
        const verified = speakeasy.totp.verify({
            secret: user.mfa_secret,
            encoding: 'base32',
            token,
        });

        if (!verified) {
            return res.status(401).send('Invalid MFA token');
        }

        // Complete login
        req.session.userId = user.id;
        delete req.session.tempUserId; // Remove temporary session
        res.send('MFA verified and login successful');
    });
});

// Authentication – MFA: Enable MFA route
app.post('/enable-mfa', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Unauthorized');
    }

    // Generate MFA secret
    const secret = speakeasy.generateSecret({ length: 20 });
    const query = 'UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?';

    db.query(query, [secret.base32, req.session.userId], (err, result) => {
        if (err) return res.status(500).send('Server error');

        res.json({
            message: 'MFA enabled',
            secret: secret.otpauth_url, // Provide QR code URL for apps like Google Authenticator
        });
    });
});

// Example route to demonstrate XSS protection
app.post('/example', (req, res) => {
    // The xssClean middleware automatically sanitizes user input
    const userInput = req.body.data;
    res.send(`Received sanitized input: ${userInput}`);
});

// Anti-SQL Injection: Login route with parameterized query
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Anti-SQL Injection: Use parameterized query to securely fetch user data
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('User not found');

        const user = results[0];

        // Password Storage: Compare the input password with the stored hashed password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Error validating password');
            if (!isMatch) return res.status(401).send('Invalid credentials');

            req.session.userId = user.id;
            res.send('Login successful');
        });
    });
});

// Anti-SQL Injection & Password Management: Registration route with parameterized query and password validation
app.post(
    '/register',
    [
        // Password Management: Enforce password strength requirements
        body('password')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
            .matches(/[0-9]/).withMessage('Password must contain at least one number')
            .matches(/[\W]/).withMessage('Password must contain at least one special character'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() }); // Return validation errors
        }

        const { username, password } = req.body;

        try {
            // Password Storage: Hash the password securely before storing in the database
            const hashedPassword = await bcrypt.hash(password, 10);

            // Anti-SQL Injection: Use parameterized query to securely insert user data
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

// Anti-SQL Injection & Password Management: Change password route
app.post(
    '/change-password',
    [
        // Password Management: Enforce password strength for new password
        body('newPassword')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
            .matches(/[0-9]/).withMessage('Password must contain at least one number')
            .matches(/[\W]/).withMessage('Password must contain at least one special character'),
    ],
    async (req, res) => {
        const { username, oldPassword, newPassword } = req.body;

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        // Anti-SQL Injection: Use parameterized query to fetch user by username
        const query = 'SELECT password FROM users WHERE username = ?';
        db.query(query, [username], async (err, results) => {
            if (err) return res.status(500).send('Server error');
            if (results.length === 0) return res.status(404).send('User not found');

            const existingHash = results[0].password;

            // Verify the old password
            const isMatch = await bcrypt.compare(oldPassword, existingHash);
            if (!isMatch) {
                return res.status(401).send('Old password is incorrect');
            }

            // Hash the new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            // Anti-SQL Injection: Use parameterized query to securely update the password
            const updateQuery = 'UPDATE users SET password = ? WHERE username = ?';
            db.query(updateQuery, [hashedPassword, username], (err, result) => {
                if (err) return res.status(500).send('Error updating password');
                res.send('Password changed successfully');
            });
        });
    }
);

// Protected route example
// Authentication - Token-Based Authentication: Protect routes using JWT
app.get('/protected', authenticateToken, (req, res) => {
    res.send(`Hello ${req.user.username}, you have access to this protected route.`);
});

// Add signature verification middleware
const verifyResponseSignature = (req, res, next) => {
    // Software Signing and Verification: Verify request signature if present
    if (req.headers['x-signature']) {
        const isValid = verifySignature(req.body, req.headers['x-signature']);
        if (!isValid) {
            return res.status(400).send('Invalid signature');
        }
    }
    next();
};

app.use(verifyResponseSignature);

// Anti-SQL Injection: Fetch messages securely
app.get('/messages', (req, res) => {
    // Anti-SQL Injection: Use safe query structure to fetch all messages
    const query = 'SELECT * FROM messages';
    db.query(query, (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.json(results);
    });
});

app.get('/', (req, res) => {
    res.send('Welcome to the Message Board!');
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
