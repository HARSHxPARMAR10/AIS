
# AIDEX Evidence Storage

## Introduction

The Evidence Storage Module is responsible for securely storing digital evidence collected during cyber crime investigations.

It ensures that evidence remains confidential, protected and easily accessible to authorized users.

---

## Objectives

The main objectives are:

- Secure Evidence Storage
- Organized File Management
- Fast Retrieval
- Data Integrity
- Secure Backup
- Easy Maintenance

---

## Storage Structure

Evidence is organized using the following structure:

Media Folder

↓

Case Folder

↓

Evidence Folder

↓

Evidence File

---

## Folder Organization

Example

media/

↓

cases/

↓

CASE_0001/

↓

evidence/

↓

image01.jpg

video01.mp4

report.pdf

---

## Stored Information

Each evidence record contains:

- Evidence ID
- Case ID
- File Name
- File Type
- File Size
- Upload Date
- Uploaded By
- SHA-256 Hash
- Storage Path

---

## Storage Rules

- Every evidence file must have a unique ID.
- Files should be organized by Case ID.
- Original files should never be modified.
- File paths should be stored in the database.
- Duplicate evidence should not be stored.

---

## Backup Policy

Regular backups should be performed.

Backup Types:

- Daily Backup
- Weekly Backup
- Monthly Backup

---

## Restore Policy

If evidence is lost:

- Retrieve from Backup
- Verify SHA-256 Hash
- Restore Database Record
- Restore File

---

## Security Measures

- Private application-controlled storage
- AES-256-GCM authenticated encryption before persistent storage
- SHA-256 Verification
- Role-Based Access
- Encrypted host backups (defence in depth)
- Audit Logging

---

## Advantages

- Secure Storage
- Organized Structure
- Easy Retrieval
- Better Investigation
- Improved Security

---

## Expected Result

The Evidence Storage module should securely store all digital evidence while maintaining integrity, confidentiality and availability.
