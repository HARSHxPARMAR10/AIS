# AIDEX Evidence Validation

## Introduction

Evidence Validation ensures that every uploaded digital evidence is authentic, complete and suitable for cyber crime investigation.

The validation process prevents duplicate, corrupted or unsupported evidence from entering the system.

---

## Validation Objectives

- Verify uploaded evidence
- Prevent duplicate uploads
- Check file integrity
- Validate metadata
- Improve evidence quality

---

## Supported File Types

The system supports:

- JPG
- JPEG
- PNG
- MP4
- AVI
- MP3
- WAV
- PDF
- DOCX
- TXT
- LOG

---

## File Size Validation

The system should:

- Reject empty files
- Reject corrupted files
- Reject oversized files
- Accept only valid file sizes

---

## File Name Validation

Rules:

- File name cannot be empty
- Special characters should be limited
- Duplicate file names should be handled
- File extension must be valid

---

## Duplicate File Detection

Duplicate detection is performed using:

- SHA-256 Hash
- File Size
- File Name
- Upload Time

---

## Metadata Validation

The system validates:

- File Name
- File Type
- Upload Date
- Created Date
- Modified Date
- File Size

---

## Hash Verification

SHA-256 Hash is generated after upload.

Purpose:

- Verify integrity
- Detect tampering
- Identify duplicate evidence

---

## Validation Result

Possible Results:

- Valid Evidence
- Duplicate Evidence
- Corrupted Evidence
- Invalid File Format
- Validation Failed

---

## Expected Result

Only verified and valid evidence should be accepted into the AIDEX system.