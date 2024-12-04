const API_BASE = "http://localhost:3000/auth";

let csrfToken = '';

// Fetch CSRF token
async function fetchCsrfToken() {
    try {
        const response = await fetch('/csrf-token', {
            credentials: 'same-origin'
        });
        const data = await response.json();
        csrfToken = data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
    }
}

// Call fetchCsrfToken on page load
fetchCsrfToken();

// Register form submit event
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;

    try {
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken // Include CSRF token
            },
            body: JSON.stringify({ username, password }),
            credentials: 'same-origin'
        });

        if (response.ok) {
            alert('Registration successful!');
        } else {
            const message = await response.text();
            alert(`Registration failed: ${message}`);
        }
    } catch (error) {
        alert('Error: Unable to register.');
    }
});

// Login form submit event
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken // Include CSRF token
            },
            body: JSON.stringify({ username, password }),
            credentials: 'same-origin'
        });

        if (response.ok) {
            alert('Login successful!');
            document.getElementById('login').style.display = 'none';
            document.getElementById('messages').style.display = 'block';
            fetchMessages(); // Load messages after successful login
        } else {
            const message = await response.text();
            alert(`Login failed: ${message}`);
        }
    } catch (error) {
        alert('Error: Unable to login.');
    }
});

// Fetch messages
async function fetchMessages() {
    const messageList = document.getElementById('messageList');
    messageList.innerHTML = 'Loading messages...';

    try {
        const response = await fetch('/messages', {
            credentials: 'same-origin'
        });

        if (!response.ok) {
            throw new Error('Failed to fetch messages');
        }

        const messages = await response.json();
        
        if (!Array.isArray(messages) || messages.length === 0) {
            messageList.innerHTML = '<li>No messages yet</li>';
            return;
        }

        messageList.innerHTML = '';
        messages.forEach(msg => {
            const li = document.createElement('li');
            li.textContent = `${msg.username}: ${msg.content}`;
            messageList.appendChild(li);
        });
    } catch (error) {
        console.error('Error:', error);
        messageList.innerHTML = '<li>Error loading messages. Please try again.</li>';
    }
}

// Add message form handler
document.getElementById('messageForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const content = e.target.content.value;

    try {
        const response = await fetch('/messages', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken // Include CSRF token
            },
            body: JSON.stringify({ content }),
            credentials: 'same-origin'
        });

        if (response.ok) {
            e.target.content.value = '';
            fetchMessages();
        } else {
            alert('Failed to send message');
        }
    } catch (error) {
        alert('Error sending message');
    }
});
