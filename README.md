
# Authentication System
This project is a Django-based authentication system designed to ensure strong security and user protection.





## Features

- User Registration 
    - CAPTCHA validation to prevent bot registrations
    - Email verification via a unique link sent to the user.
- Login
    - MFA using One-Time Password (OTP) sent   to the user’s email after successful password entry.
- Password Security
    - Enforces password strength (min. 8 characters, at least one uppercase letter, number, and special character).
    - Password hashing using Django’s default security algorithms.
- Password Reset
    - Email-based password reset with validation.
    - Prevents reusing the last 3 passwords.
- Email Verification
    - Ensures the validity of email addresses before granting full access.








## Installation

Prerequisites:
- Python 3.x
- Django 3.x or above
- A working email SMTP server for email verification and OTP
- Google reCAPTCHA keys (for CAPTCHA integration)

Clone the repository

```bash
git clone https://github.com/Kaustuv-b/Advanced-CyberSecurity-Assingment.git

cd Advanced-CyberSecurity-Assingment
```

Install Required packages 

```bash
    pip install django 
    pip install django-reCAPTCHA
```

Set up environment variables for:

- Email SMTP settings (e.g., EMAIL_HOST, EMAIL_PORT, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)

- reCAPTCHA secret key

Apply migrations 

```bash 
    python manage.py migrate 
```

Run the development server 

```bash
    python manage.py runserver
```

## Usage

User Registration:

- Access the registration page at /register/.
- Complete the CAPTCHA and verify the email address.

Login: 

- Access the login page at /login/.
- After entering valid credentials, an OTP will be sent to the registered email for verification.

Password Reset:

- Visit /forgot-password/ to reset the password via email.

MFA Verification:

- After login, enter the OTP sent to your email to complete authentication.


## Contact

For any issues, contact kca22.24kb@gmail.com

#
