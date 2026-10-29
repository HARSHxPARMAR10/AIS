# AIDEX Case Validation

## Introduction

Case Validation ensures that every cyber crime case entered into the AIDEX system is complete, accurate and valid before it is stored in the database.

The validation process prevents incomplete, duplicate or incorrect case records.

---

## Validation Objectives

The main objectives are:

- Verify Case Information
- Prevent Duplicate Cases
- Ensure Required Fields
- Improve Data Accuracy
- Maintain Investigation Quality

---

## Mandatory Fields

Every case must contain:

- Case ID
- Case Number
- Case Title
- Case Description
- Crime Category
- Investigator Name
- Priority
- Status
- Created Date

---

## Case Number Validation

Rules:

- Must be unique
- Cannot be empty
- Cannot contain invalid characters

---

## Title Validation

Rules:

- Title cannot be empty
- Minimum meaningful length required
- Special characters should be limited

---

## Investigator Validation

Rules:

- Investigator must exist in the system
- Investigator role must be valid
- One investigator can manage multiple cases

---

## Priority Validation

Supported Priorities:

- Low
- Medium
- High
- Critical

---

## Status Validation

Supported Status:

- Open
- Assigned
- Under Investigation
- Pending
- Closed

---

## Validation Result

Possible Results:

- Valid Case
- Duplicate Case
- Missing Information
- Invalid Data
- Validation Failed

---

## Expected Result

Only valid and complete cyber crime cases should be stored inside the AIDEX database.