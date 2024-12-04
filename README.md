# Message Board Application

A secure and user-friendly message board application built with Node.js, Express.js, and MySQL. This application implements key security practices such as input validation, anti-XSS/CSRF techniques, password management, and token-based authentication using JWT.

---

## **Features**

- User registration and login
- Multi-factor authentication (MFA)
- Secure password storage using `bcrypt`
- Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) protection
- Token-based authentication with JWT
- Message posting and retrieval functionality
- Secure storage of sensitive information

---

## **Installation Guide**

### **1. Clone the Repository**

To clone this repository, open your terminal and run the following command:

```bash
git clone https://github.com/CankunNa/message-board-group4.git
```

Navigate to the project directory:

```bash
cd message-board
```

---

### **2. Install Dependencies**

Ensure you have [Node.js](https://nodejs.org/) and [MySQL](https://www.mysql.com/) installed. Then, install the necessary dependencies:

```bash
npm install
```

---

### **3. Configure Environment Variables**

Create a `.env` file in the root of the project and add the following configuration. Replace the placeholders with your database and secret key values:

```env
# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=message_board

# Authentication Secrets
JWT_SECRET=your_jwt_secret_key
SESSION_SECRET=your_session_secret_key

# Software Signing Keys
PRIVATE_KEY=-----BEGIN PRIVATE KEY-----
...your-private-key...
-----END PRIVATE KEY-----
PUBLIC_KEY=-----BEGIN PUBLIC KEY-----
...your-public-key...
-----END PUBLIC KEY-----
```

---

### **4. Setup the Database**

Log in to your MySQL server and execute the following SQL commands to create the database and tables:

```sql
-- Create the database
CREATE DATABASE message_board;

-- Use the newly created database
USE message_board;

-- Create the users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT FALSE
);

-- Create the messages table
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content TEXT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

### **5. Start the Application**

Run the following command to start the application:

```bash
node server.js
```

The application will be available at: [http://localhost:3000](http://localhost:3000)

---

### **6. Access the Application**

- **Register a New User**: Navigate to the `/register` route to create a new account.
- **Login**: Use your credentials to log in via the `/login` route.
- **Post Messages**: Once logged in, post messages via the `/messages` route.

---

## **API Endpoints**

### **Authentication**

- `POST /auth/register`: Register a new user.
- `POST /auth/login`: Login and receive a JWT.
- `POST /auth/enable-mfa`: Enable MFA for the current user.
- `POST /auth/verify-mfa`: Verify MFA during login.

### **Messages**

- `GET /messages`: Retrieve all messages.
- `POST /messages`: Post a new message (requires authentication).

---

## **Technologies Used**

- **Backend**: Node.js, Express.js
- **Database**: MySQL
- **Authentication**: JWT, bcrypt
- **Security**: Helmet, xss-clean, csurf
- **Environment Management**: dotenv

---

## **Contributing**

1. Fork the repository.

2. Create a new branch:

   ```bash
   git checkout -b feature-branch
   ```

3. Make your changes and commit:

   ```bash
   git commit -m "Add feature"
   ```

4. Push to your branch:

   ```bash
   git push origin feature-branch
   ```

5. Submit a pull request.

---

## **License**

This project is licensed under the MIT License. See the LICENSE file for details.
