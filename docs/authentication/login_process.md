# AIDEX Login Process

## Introduction

The Login Process allows registered users to securely access the AIDEX system using their valid credentials.

Only authenticated users are permitted to enter the system.

---

## Login Workflow

```text
Open Login Page
        ↓
Enter Username
        ↓
Enter Password
        ↓
Validate Credentials
        ↓
Authentication Successful
        ↓
Create User Session
        ↓
Redirect to Dashboard
```

---

## Login Information

The login form requires:

- Username
- Password

---

## Authentication Process

The system performs the following checks:

- Verify Username
- Verify Password
- Check Account Status
- Load User Role
- Create Secure Session

---

## Failed Login

Possible reasons for login failure:

- Invalid Username
- Incorrect Password
- Inactive Account
- Suspended Account
- Unauthorized User

---

## Security Features

- Password Hash Verification
- CSRF Protection
- Session Authentication
- Role-Based Authorization
- Secure Logout

---

## Successful Login

If authentication is successful:

- User session is created
- User role is loaded
- Dashboard is displayed
- Login time is recorded

---

## Expected Result

Only authorized users should successfully access the AIDEX dashboard after completing the login process.