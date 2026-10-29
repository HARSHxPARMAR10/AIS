# AIDEX File Validation Documentation

## Overview

The File Validation module is responsible for validating every
uploaded digital evidence file before it is processed by the AI Engine.

Its primary objective is to ensure that only supported, safe and
properly formatted files are accepted into the system.

---

# Objectives

The File Validation module performs the following tasks:

- Validate uploaded file extensions
- Validate file size
- Detect MIME type
- Generate safe filenames
- Prevent dangerous file uploads
- Extract metadata
- Categorize evidence files

---

# Supported File Types

## Images

- JPG
- JPEG
- PNG
- BMP
- GIF
- WEBP

---

## Documents

- PDF
- DOC
- DOCX
- TXT

---

## Videos

- MP4
- AVI
- MOV

---

## Audio

- MP3
- WAV

---

# Validation Process

The validation process follows the steps below:

```
User Upload
      │
      ▼
Filename Validation
      │
      ▼
Extension Validation
      │
      ▼
File Size Validation
      │
      ▼
MIME Type Detection
      │
      ▼
Safe Filename Generation
      │
      ▼
Metadata Extraction
      │
      ▼
Evidence Accepted
```

---

# File Extension Validation

The system checks whether the uploaded file extension is included in the
list of supported evidence formats.

Unsupported extensions are rejected immediately.

---

# Dangerous File Detection

Executable or potentially harmful file types are blocked.

Examples include:

- EXE
- BAT
- CMD
- DLL
- MSI
- JS
- VBS
- PS1
- SH

---

# File Size Validation

The maximum upload size is controlled through the configuration file.

Example:

```
Maximum Upload Size = 25 MB
```

Files larger than the configured limit are rejected.

---

# MIME Type Detection

The system determines the probable MIME type based on the uploaded file.

Examples:

| Extension | MIME Type |
|-----------|-----------|
| .jpg | image/jpeg |
| .png | image/png |
| .pdf | application/pdf |
| .docx | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| .mp4 | video/mp4 |

---

# Safe Filename Generation

Uploaded filenames are sanitized before storage.

Example:

Original

```
Cyber Crime Report (Final).pdf
```

Generated

```
cyber_crime_report_final_a1b2c3d4.pdf
```

This helps prevent filename conflicts and improves security.

---

# Metadata Extraction

The module extracts useful metadata including:

- Original filename
- Safe filename
- File extension
- File category
- MIME type
- File size
- Absolute path
- Last modified timestamp

---

# Security Features

The validation module provides:

- Path traversal protection
- Dangerous extension blocking
- Invalid filename detection
- Empty file detection
- Maximum file size enforcement

---

# Benefits

The File Validation module:

- Protects the AI Engine
- Ensures evidence consistency
- Prevents unsupported uploads
- Improves system security
- Supports future AI processing

---

# Conclusion

The File Validation module forms the first security layer of the
AIDEX AI Engine by ensuring that only valid and supported digital
evidence files are accepted for further analysis.