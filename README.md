# Bookmark Manager - Backend

This is the backend for the Bookmark Manager full-stack web application. It provides authentication, bookmark management, and user session handling.

## 📌 Features

•  User authentication (Signup, Login, Logout, Logout from all devices)
•  Secure token-based authentication using JWT
•  Bookmark CRUD operations (Create, Read, Update, Delete)
•  MongoDB as the database with Mongoose ORM
•  Middleware for authentication and error handling

## 🛠️ Tech Stack

•  Node.js (Runtime Environment)
•  Express.js (Web Framework)
•  MongoDB (Database)
•  Mongoose (ODM for MongoDB)
•  bcrypt (Password Hashing)
•  jsonwebtoken (JWT Authentication)
•  dotenv (Environment Variable Management)
•  CORS (Cross-Origin Resource Sharing)

## 🛡️ Middleware & Security

•  Authentication Middleware ensures only authenticated users can access protected routes.
•  Hashing Passwords using bcrypt to store passwords securely.
•  JWT Token Expiry for session management.
•  CORS enabled to allow frontend access.