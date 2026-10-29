AIDEX Database Design

Main Tables

- Users
- Cases
- Evidence
- Reports
- Audit Logs

Purpose:
Store all cyber crime investigation data securely using MySQL.

# AIDEX Database Design

## Introduction

The AIDEX Database is designed to securely store cyber crime investigation records, user information, digital evidence, AI analysis results and investigation reports.

The database provides secure storage, fast retrieval and proper relationship management between all modules.

---

## Objectives

The main objectives of the database are:

- Store User Information
- Store Cyber Crime Cases
- Store Digital Evidence
- Store AI Analysis Results
- Store Investigation Reports
- Store Audit Logs
- Maintain Data Integrity
- Provide Fast Data Retrieval

---

## Database Technology

Database Management System:

MySQL

---

## Database Features

- Secure Storage
- High Performance
- Data Integrity
- Relationship Support
- Backup Support
- Easy Maintenance
- Scalable Architecture

---

## Main Database Tables

1. Users

Stores all registered users.

2. Cases

Stores cyber crime case details.

3. Evidence

Stores uploaded digital evidence.

4. AI Analysis

Stores AI generated evidence analysis.

5. Reports

Stores investigation reports.

6. Audit Logs

Stores user activity logs.

---

## Primary Keys

Users

User_ID

Cases

Case_ID

Evidence

Evidence_ID

AI Analysis

Analysis_ID

Reports

Report_ID

Audit Logs

Log_ID

---

## Foreign Keys

Cases → User_ID

Evidence → Case_ID

AI Analysis → Evidence_ID

Reports → Case_ID

Audit Logs → User_ID

---

## Data Integrity Rules

- Every user must have a unique username.
- Every email must be unique.
- Every badge ID must be unique.
- Every case must belong to one investigator.
- Every evidence file must belong to one case.
- Reports cannot exist without a case.
- Audit logs must always reference a valid user.

---

## Database Security

- Passwords are salted and hashed by Django's password framework.
- User authentication required.
- Role-based access control.
- Audit logging enabled.
- Evidence integrity verification.
- Backup supported.

---

## Expected Result

The database should provide secure, reliable and scalable storage for all AIDEX modules while maintaining data consistency and integrity.
