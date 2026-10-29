# Entity Relationship Diagram

## AIDEX Database Entity Relationship

```
                    USER
                      │
          ┌───────────┼───────────┐
          │           │           │
          │           │           │
        CASES     AUDIT LOGS   REPORTS
          │
          │
      EVIDENCE
```

## Relationship Explanation

### 1. User → Cases
One User can create and manage multiple cyber crime cases.
Each Case belongs to one authorized User such as an Administrator, Investigator or Cyber Officer.

### 2. Case → Evidence
One Case can contain multiple evidence records.
Each Evidence record belongs to only one Case.

### 3. Case → Reports
One Case can have multiple investigation reports.
Reports are generated during different stages of the investigation.

### 4. User → Audit Logs
Every action performed by a User is recorded in the Audit Log.
This helps maintain accountability and system security.

### Relationship Summary

- One User → Many Cases
- One Case → Many Evidence
- One Case → Many Reports
- One User → Many Audit Logs

## Purpose

The Entity Relationship (ER) Diagram defines how all database tables are connected with each other. It helps developers understand data flow, maintain referential integrity, and design a secure database structure for the AIDEX Cyber Crime Evidence Management System.

# AIDEX Entity Relationship Diagram

## Introduction

The Entity Relationship Diagram (ER Diagram) illustrates how different entities of the AIDEX system are connected.

---

## ER Diagram

```text
Users
   │
   ▼
Cases
   │
   ▼
Evidence
   │
   ▼
AI Analysis
   │
   ▼
Reports
   │
   ▼
Audit Logs
```

---

## Relationships

### Users → Cases

One User can manage multiple Cases.

Relationship:

One-to-Many

---

### Cases → Evidence

One Case can contain multiple Evidence files.

Relationship:

One-to-Many

---

### Evidence → AI Analysis

Each Evidence file can have one AI Analysis result.

Relationship:

One-to-One

---

### Cases → Reports

One Case can generate multiple Reports.

Relationship:

One-to-Many

---

### Users → Audit Logs

One User can generate multiple Audit Logs.

Relationship:

One-to-Many

---

## Expected Result

The ER Diagram clearly defines relationships between all major database entities used in AIDEX.