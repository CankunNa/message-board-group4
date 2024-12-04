const express = require('express');
const db = require('../db');
const router = express.Router();

// Fetch messages route
router.get('/', (req, res) => {
    const query = 'SELECT m.content, u.username FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.id DESC';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Error fetching messages' });
        }
        res.json(results);
    });
});

// Post new message route
router.post('/', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Please login to post messages');
    }

    const { content } = req.body;
    if (!content || content.trim() === '') {
        return res.status(400).send('Message content cannot be empty');
    }

    const query = 'INSERT INTO messages (content, user_id) VALUES (?, ?)';
    db.query(query, [content, req.session.userId], (err, result) => {
        if (err) {
            console.error('Message post error:', err);
            return res.status(500).send('Error posting message');
        }
        res.status(201).send('Message posted successfully');
    });
});

module.exports = router;
