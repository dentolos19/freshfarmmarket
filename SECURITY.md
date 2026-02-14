# Security Checklist

## Registration and User Data Management

- [x] Implement successful saving of member info into the database
- [x] Check for duplicate email addresses and handle appropriately
- [x] Implement strong password requirements:
  - [x] Minimum 12 characters
  - [x] Combination of lowercase, uppercase, numbers, and special characters
  - [x] Provide feedback on password strength
  - [x] Implement both client-side and server-side password checks
- [x] Encrypt sensitive user data in the database (e.g., NRIC, credit card numbers)
- [x] Implement proper password hashing and storage
- [x] Implement file upload restrictions (e.g., .docx, .pdf, or .jpg only)

## Session Management

- [x] Create a secure session upon successful login
- [x] Implement session timeout
- [x] Route to homepage/login page after session timeout
- [x] Detect and handle multiple logins from different devices/browser tabs

## Login/Logout Security

- [x] Implement proper login functionality
- [x] Implement rate limiting (e.g., account lockout after 3 failed login attempts)
- [x] Perform proper and safe logout (clear session and redirect to login page)
- [x] Implement audit logging (save user activities in the database)
- [x] Redirect to homepage after successful login, displaying user info

## Anti-Bot Protection

- [x] Implement Google reCAPTCHA v3 service

## Input Validation and Sanitization

- [x] Prevent injection attacks (e.g., SQL injection)
- [x] Implement Cross-Site Request Forgery (CSRF) protection
- [x] Prevent Cross-Site Scripting (XSS) attacks
- [x] Perform proper input sanitization, validation, and verification for all user inputs
- [x] Implement both client-side and server-side input validation
- [x] Display error or warning messages for improper input
- [x] Perform proper encoding before saving data into the database

## Error Handling

- [x] Implement graceful error handling on all pages
- [x] Create and display custom error pages (e.g., 404, 403)

## Software Testing and Security Analysis

- [x] Perform source code analysis using external tools (e.g., GitHub)
- [x] Address security vulnerabilities identified in the source code

## Advanced Security Features

- [x] Implement automatic account recovery after lockout period
- [x] Enforce password history (avoid password reuse, max 2 password history)
- [x] Implement change password functionality
- [x] Implement reset password functionality (using email link)
- [x] Enforce minimum password age policy (5 minutes between changes)
- [x] Enforce maximum password age policy (90 days, forced change on login)
- [x] Implement Two-Factor Authentication (2FA)

## General Security Best Practices

- [x] Use HTTPS for all communications
- [x] Implement proper access controls and authorization
- [x] Keep all software and dependencies up to date (as of 2026-02-14)
- [x] Follow secure coding practices
- [ ] Regularly backup and securely store user data
- [x] Implement logging and monitoring for security events
