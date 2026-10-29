# AIDEX Case Workflow

## Introduction

The Case Workflow defines the complete investigation process followed inside the AIDEX system.

Every cyber crime case follows a predefined workflow to ensure proper investigation and documentation.

---

## Workflow Diagram

```text
Create Case
      ↓
Assign Investigator
      ↓
Upload Evidence
      ↓
Evidence Verification
      ↓
AI Analysis
      ↓
Generate Report
      ↓
Close Case
```

---

## Step 1

### Create Case

Administrator or Investigator creates a new cyber crime case.

The system generates a unique Case ID.

---

## Step 2

### Assign Investigator

The case is assigned to a responsible investigator.

Assignment details are stored in the database.

---

## Step 3

### Upload Evidence

Digital evidence related to the case is uploaded.

Evidence is linked with the Case ID.

---

## Step 4

### Evidence Verification

Uploaded evidence is verified using:

- SHA-256 Hash
- File Metadata
- Duplicate Detection

---

## Step 5

### AI Analysis

The AI engine analyzes uploaded evidence.

The generated results help investigators identify useful information.

---

## Step 6

### Generate Report

The investigator prepares the final investigation report.

Reports are stored in the Reports module.

---

## Step 7

### Close Case

After investigation completion, the case status is changed to Closed.

---

## Expected Result

Every cyber crime case should follow a secure, organized and traceable workflow.