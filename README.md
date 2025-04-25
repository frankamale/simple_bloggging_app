Simple Express.js Backend
A lightweight backend API built with Express.js that supports user authentication and basic CRUD operations for posts. Users can sign up, log in, create, update, and delete their posts.

🚀 Features
🔐 User Sign Up & Login (with hashed passwords)
📬 JWT-based Authentication
🧾 CRUD operations for Posts
🛡️ Protected routes with middleware

🧰 Tech Stack
Backend: Express.js
Authentication: JSON Web Tokens (JWT) & bcrypt
Database: Sqlite
Runtime: Node.js

📁 Project Structure

/project-root
│
├── /routes        # Route definitions
├── /models        #
├── /middleware    # Auth middleware (e.g., verifyToken)
├── /config        # DB config (e.g., connectDB.js)
├── server.js      # Entry point
└── .env           # Environment variables
🧪 Testing


