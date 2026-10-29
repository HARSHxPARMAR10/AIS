# Table Relationships

## Introduction

The AIDEX database contains multiple tables that are connected using Primary Keys and Foreign Keys. These relationships help maintain data integrity and improve database performance.

---

## User → Cases

Relationship:
One User can manage multiple Cases.

Description:
An Administrator or Investigator can create and manage several cyber crime cases. Every Case belongs to one responsible User.

Relationship Type:
One-to-Many (1:N)

---

## Case → Evidence

Relationship:
One Case can contain multiple Evidence records.

Description:
Every cyber crime case may have multiple digital evidence files including images, videos, documents, emails, logs, and other forensic data.

Relationship Type:
One-to-Many (1:N)

---

## Case → Reports

Relationship:
One Case can have multiple Reports.

Description:
During investigation, different reports may be generated for the same case.

Relationship Type:
One-to-Many (1:N)

---

## User → Audit Logs

Relationship:
One User can generate multiple Audit Log entries.

Description:
Every login, logout, upload, update, delete, and report generation activity performed by a user is recorded in the Audit Log.

Relationship Type:
One-to-Many (1:N)

---

## Summary

Database Relationships

User
│
├── Cases
│      │
│      ├── Evidence
│      │
│      └── Reports
│
└── Audit Logs

---

## Benefits

- Maintains Data Integrity
- Prevents Duplicate Records
- Improves Database Performance
- Supports Secure Cyber Crime Investigation
- Maintains Proper Record Linking

# AIDEX Table Relationships

## Introduction

Table Relationships define how different database tables are connected to each other.

These relationships help maintain data consistency and improve database performance.

---

## Relationship 1

Users → Cases

Relationship Type:

One-to-Many

Description:

One User can create and manage multiple cyber crime cases.

---

## Relationship 2

Cases → Evidence

Relationship Type:

One-to-Many

Description:

One Case may contain multiple digital evidence files.

---

## Relationship 3

Evidence → AI Analysis

Relationship Type:

One-to-One

Description:

Each uploaded evidence file can generate one AI analysis report.

---

## Relationship 4

Cases → Reports

Relationship Type:

One-to-Many

Description:

One Case may generate multiple investigation reports.

---

## Relationship 5

Users → Audit Logs

Relationship Type:

One-to-Many

Description:

Each User can generate multiple activity logs while using the system.

---

## Relationship Summary

Users
↓

Cases
↓

Evidence
↓

AI Analysis
↓

Reports
↓

Audit Logs

---

## Expected Result

The table relationships provide a structured and connected database architecture for the AIDEX system.