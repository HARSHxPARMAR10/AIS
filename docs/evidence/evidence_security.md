# AIDEX Evidence Security

## Introduction

Evidence Security protects digital evidence from unauthorized access, modification and deletion.

The security module ensures confidentiality, integrity and availability of evidence.

---

## Security Objectives

- Protect Evidence
- Prevent Unauthorized Access
- Ensure Data Integrity
- Maintain Confidentiality
- Secure Digital Storage

---

## Security Techniques

The application uses:

- AES-256-GCM Authenticated Encryption
- SHA-256 Hash
- Role-Based Access Control
- Authentication
- Authorization
- Protected media responses

---

## Encryption at Rest

AIDEX encrypts every newly uploaded evidence file with AES-256-GCM before the
file is persisted. Each file receives a random 96-bit nonce and an
authentication tag. The master 256-bit key is loaded only from `.env` or the
deployment secret manager and is never stored in the database or ciphertext.

Existing plaintext files are converted with:

```text
python manage.py encrypt_existing_evidence
```

Authorized reads authenticate the complete ciphertext before returning
plaintext. Wrong keys and modified ciphertext are rejected. OCR and selected
provider SDKs receive a permission-restricted temporary plaintext file that is
removed immediately after the operation; production should place temporary
files on an encrypted volume.

---

## SHA-256 Hash

SHA-256 is used to:

- Verify file integrity
- Detect file modification
- Detect duplicate evidence

---

## Role-Based Access

Access Levels:

Administrator

- Full Access

Investigator

- Upload and View Evidence

Cyber Officer

- Verify and Approve Evidence

---

## Secure Upload

During upload:

- File Type Validation
- File Size Validation
- Hash Generation
- Metadata Verification

---

## Audit Logs

Workflow and security-relevant activity should be recorded, including:

- Upload
- Verification
- Archive and restore

---

## Backup Strategy

Evidence should be backed up regularly to prevent data loss.

---

## Security Advantages

- Better Protection
- Secure Storage
- Data Integrity
- Reliable Investigation
- Easy Tracking

---

## Expected Result

The Evidence Security module combines AES-256-GCM confidentiality and
authentication, SHA-256 forensic integrity, and controlled access. Encrypted
host storage and backups remain recommended as defence in depth.
