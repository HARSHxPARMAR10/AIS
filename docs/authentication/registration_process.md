# AIDEX User Registration Process

## Introduction

The User Registration Process allows authorized users to create an account in the AIDEX system.

Each registration is validated before storing user information.

---

## Registration Workflow

```text
Open Registration Page
        ↓
Enter User Details
        ↓
Validate Information
        ↓
Create User Account
        ↓
Encrypt Password
        ↓
Store User Data
        ↓
Registration Successful
```

---

## Registration Fields

The registration form collects:

- Full Name
- Username
- Email Address
- Password
- Phone Number
- Department
- Badge ID
- Role
- Profile Photo

---

## Validation Rules

- Username must be unique
- Email must be unique
- Badge ID must be unique
- Password cannot be empty
- Required fields must be completed

---

## Password Security

The password is:

- Hashed before storage
- Never stored in plain text
- Protected using Django Authentication

---

## Registration Result

If validation succeeds:

- User Account Created
- User Profile Stored
- Registration Completed

If validation fails:

- Error Message Displayed
- User Corrects Information
- Registration Retry

---

## Expected Result

Every registered user should have a secure account with unique credentials and role-based access.