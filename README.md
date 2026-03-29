# 🍕 Bonnyrigg Pizza Blog 

A secure Flask-based pizza recipe blog application with comprehensive security features including Two-Factor Authentication (2FA), CSRF protection, and brute force attack prevention.

## 📋 Table of Contents
- [Features](#features)
- [Security Features](#security-features)
- [Prerequisites](#prerequisites)

## ✨ Features

- **User Authentication** - Secure registration and login with password hashing
- **Blog Posts** - Create, read, and manage pizza recipe posts
- **Image Uploads** - Upload and display pizza images with secure file handling
- **User Dashboard** - Personal dashboard to manage your posts
- **Session Management** - Secure session handling with automatic timeout
- **Graceful Error Handling** - Custom 404 and 500 error pages

## 🔒 Security Features

This application implements multiple security layers to protect against common web vulnerabilities:

### 1. **Two-Factor Authentication (2FA)** 🔐
- TOTP-based 2FA using authenticator apps (Google Authenticator, Authy, etc.)
- QR code generation for easy setup
- Optional enable/disable per user account

### 2. **CSRF Protection** 🛡️
- Unique CSRF tokens generated per session
- Token validation on all POST requests
- Prevention of Cross-Site Request Forgery attacks

### 3. **Brute Force Protection** 🚫
- Maximum 5 failed login attempts
- 15-minute account lockout after exceeding attempts
- IP-based tracking with email identification
- Automatic attempt cleanup after successful login

### 4. **SQL Injection Prevention** 💉
- Parameterized queries throughout the application
- No direct string concatenation in SQL statements

### 5. **Password Security** 🔑
- Passwords hashed using Werkzeug's secure hashing
- Strong password requirements (minimum 8 chars, uppercase & lowercase)
- No plain-text password storage

### 6. **Input Validation** ✅
- Email format validation
- Strong password validation
- File type validation for uploads
- Secure filename handling

### 7. **Session Security** 🔒
- HTTP-only cookies prevent JavaScript access
- SameSite=Lax cookie attribute
- 30-minute session timeout
- Session regeneration on login

### 8. **Security Headers** 🛡️
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block

### 9. **Graceful Error Handling** ⚠️
- Custom error pages for 404 and 500 errors
- No sensitive information leakage in error messages

## 📦 Prerequisites

- Python 3.7 or higher
- pip (Python package manager)
- Virtual environment (recommended)
