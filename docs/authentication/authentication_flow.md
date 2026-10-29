# AIDEX Authentication Flow

## Introduction

The Authentication Flow defines how users securely access the AIDEX system.

Every user must successfully complete authentication before accessing any protected module.

---

## Authentication Workflow

```text
User Opens Login Page
          ↓
Enter Username & Password
          ↓
System Validates Credentials
          ↓
Authentication Success
          ↓
Load User Role
          ↓
Redirect to Dashboard
```

---

## Step 1 – User Login

The user opens the login page and enters:

- Username
- Password

---

## Step 2 – Credential Validation

The system validates:

- Username exists
- Password is correct
- Account is active
- User role is available

---

## Step 3 – Authentication

If validation succeeds:

- Create Session
- Store User ID
- Store User Role
- Store Login Time

---

## Step 4 – Dashboard Access

The authenticated user is redirected according to role.

Administrator

↓

Admin Dashboard

Investigator

↓

Investigator Dashboard

Cyber Officer

↓

Officer Dashboard

---

## Authentication Failure

Possible Reasons

- Invalid Username
- Wrong Password
- Suspended Account
- Inactive Account
- Unauthorized Access

---

## Security Features

- Password Hashing
- Session Authentication
- Role-Based Access Control
- CSRF Protection
- Secure Logout

---

## Expected Result

Only authenticated users should be allowed to access protected modules inside the AIDEX system.