# AIDEX Database Constraints

## Introduction

Database Constraints help maintain data integrity, consistency and security.

---

## Primary Keys

Users

- User_ID

Cases

- Case_ID

Evidence

- Evidence_ID

Reports

- Report_ID

AI Analysis

- Analysis_ID

Audit Logs

- Log_ID

---

## Foreign Keys

Cases → User_ID

Evidence → Case_ID

Reports → Case_ID

AI Analysis → Evidence_ID

Audit Logs → User_ID

---

## Unique Constraints

- Username
- Email
- Badge_ID
- Case_ID
- Evidence_ID

---

## NOT NULL Constraints

- Full Name
- Username
- Password
- Role
- Case Title
- Evidence File Name

---

## Default Values

User Status

- Active

Case Status

- Open

Evidence Status

- Pending Verification

---

## Cascade Rules

Delete Case

↓

Delete Related Evidence

↓

Delete AI Analysis

---

## Validation Rules

- Username must be unique.
- Email must be valid.
- Badge ID must be unique.
- Case Title cannot be empty.
- Evidence must belong to a valid Case.
- Reports require a valid Case.

---

## Expected Result

The database constraints ensure secure, accurate and reliable data storage.