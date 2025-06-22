Auth Service
Auth Service is a secure, scalable web service built with Axum, a modern Rust web framework. It provides robust authentication features, including two-factor authentication (2FA), notification systems, chat functionality, and payment processing integration. This project serves as a foundation for building secure and feature-rich applications that require user authentication and real-time communication.
Features

Authentication: Secure login and registration with JWT-based tokens.
Two-Factor Authentication (2FA): Optional TOTP-based 2FA for enhanced security.
Notifications: Support for multiple notification types (email, SMS, WebSocket, Firebase).
Chat Service: Real-time chat with AI response simulation.
Payment Processing: Simulated subscription and Solana-based payment handling.

Prerequisites
Before running the project, ensure you have the following installed:

Rust (edition 2024 or later)
PostgreSQL (for the database)
Redis (for caching and session management)

You will also need to set up the following environment variables:

DATABASE_URL: Connection string for the PostgreSQL database (e.g., postgres://user:password@localhost/auth_db).
REDIS_URL: Connection string for the Redis server (e.g., redis://localhost/).
JWT_SECRET: A secret key for signing JWT tokens (e.g., your-secret-key).

Setup

Clone the repository:
git clone https://github.com/your-username/auth-service.git
cd auth-service


Install dependencies:Ensure you have the necessary Rust crates by running:
cargo build


Set up the database:

Create a PostgreSQL database named auth_db (or your preferred name).
Update the DATABASE_URL environment variable with your database connection details.
Run the following SQL to create the users table:CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    avatar_url VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    two_factor_secret VARCHAR(255),
    webauthn_credential TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);




Configure environment variables:Set the required environment variables in your shell or in a .env file (if using a tool like dotenv):
export DATABASE_URL=postgres://user:password@localhost/auth_db
export REDIS_URL=redis://localhost/
export JWT_SECRET=your-secret-key



Running the Project
To start the server, run the following command:
cargo run

The server will start on 0.0.0.0:5000 by default. You can access the health check endpoint at http://localhost:5000/health to verify that the service is running.
Usage
The following endpoints are available:

Authentication:

POST /login: Authenticate a user and receive a JWT token.
Requires: email, password, and optionally totp_code (if 2FA is enabled).


POST /register: Register a new user.
Requires: email, password, and optionally role.




Two-Factor Authentication:

POST /enable-2fa: Enable 2FA for a user and receive a QR code for TOTP setup.
Requires: User data (typically sent after authentication).




Notifications:

POST /send-notification: Send a notification via email, SMS, WebSocket, or Firebase.
Requires: user_id, message, notification_type, and target.




Chat Service:

POST /chat-service: Send a chat message and receive an AI-generated response.
Requires: user_id and message.




Payment Processing:

POST /payment-subscription: Simulate a subscription payment.
Requires: user_id, amount, currency, and optionally subscription_type.





Example Requests
You can use tools like curl or Postman to interact with the API. Below are some sample requests:

Register a user:
curl -X POST http://localhost:5000/register \
-H "Content-Type: application/json" \
-d '{"email": "user@example.com", "password": "securepassword", "role": "user"}'


Login:
curl -X POST http://localhost:5000/login \
-H "Content-Type: application/json" \
-d '{"email": "user@example.com", "password": "securepassword"}'


Enable 2FA:
curl -X POST http://localhost:5000/enable-2fa \
-H "Content-Type: application/json" \
-d '{"id": 1, "email": "user@example.com"}'


Send a notification:
curl -X POST http://localhost:5000/send-notification \
-H "Content-Type: application/json" \
-d '{"user_id": 1, "message": "Hello!", "notification_type": "email", "target": "user@example.com"}'



Testing
To test the project, you can use the sample requests above or create your own using tools like curl, Postman, or any HTTP client. Ensure that the database and Redis are running and properly configured.
Contributing
Contributions are welcome! If you find any issues, have suggestions for improvements, or want to add new features, please:

Report issues or suggest features via GitHub Issues.
Submit pull requests with your changes, following Rust coding conventions.
