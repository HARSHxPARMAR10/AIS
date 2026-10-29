# AIDEX Role Permissions

## Introduction

The AIDEX system follows Role-Based Access Control (RBAC).

Every authenticated user is assigned a specific role that determines the modules and features they can access.

---

## Available Roles

The system supports three user roles:

- Administrator
- Investigator
- Cyber Officer

---

## Administrator Permissions

Administrator has complete access to the system.

Responsibilities:

- Manage Users
- Manage Cases
- Assign Investigators
- Approve Accounts
- View Reports
- Manage Dashboard
- Configure System Settings

---

## Investigator Permissions

Investigator is responsible for handling cyber crime investigations.

Responsibilities:

- View Assigned Cases
- Upload Evidence
- Verify Evidence
- Update Investigation Status
- Generate Reports

---

## Cyber Officer Permissions

Cyber Officers assist investigators and review investigation progress.

Responsibilities:

- View Cases
- Review Evidence
- Perform AI Analysis
- Monitor Investigation Progress
- View Reports

---

## Access Control

Each role has different permissions.

Unauthorized users cannot access restricted modules.

---

## Security Features

- Role Verification
- Permission Validation
- Secure Authorization
- Protected Routes
- Session Verification

---

## Expected Result

Every authenticated user should access only those modules and features that are permitted according to their assigned role.