# AIDEX Database Flow

## Introduction

Database Flow describes how data moves through different modules of the AIDEX system during a cyber crime investigation.

---

## Database Flow Diagram

```text
Administrator
      │
      ▼
User Registration
      │
      ▼
Create Cyber Crime Case
      │
      ▼
Upload Digital Evidence
      │
      ▼
AI Analysis
      │
      ▼
Generate Investigation Report
      │
      ▼
Store Audit Log
```

---

## Step 1

### User Registration

The Administrator creates or approves a user account.

The user information is stored in the Users table.

---

## Step 2

### Case Registration

The Investigator creates a new cyber crime case.

The case information is stored in the Cases table.

---

## Step 3

### Evidence Upload

Digital evidence is uploaded for the selected case.

Evidence details are stored in the Evidence table.

---

## Step 4

### AI Analysis

The uploaded evidence is processed by the AI Engine.

Analysis results are stored in the AI Analysis table.

---

## Step 5

### Report Generation

The system generates investigation reports based on the case and evidence.

Reports are stored in the Reports table.

---

## Step 6

### Audit Logging

Every important system activity is recorded.

Audit information is stored in the Audit Logs table.

---

## Advantages

- Secure Data Flow
- Organized Investigation Process
- Better Data Management
- AI Integration
- Easy Report Generation
- Complete Audit Trail

---

## Expected Result

The database flow ensures that every stage of the cyber crime investigation is securely recorded and properly linked within the AIDEX database.