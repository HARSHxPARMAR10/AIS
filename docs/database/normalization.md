# Database Normalization

## Introduction

Database Normalization is the process of organizing database tables to eliminate data redundancy and improve data consistency. It helps maintain accurate and efficient storage of cyber crime investigation records.

---

# First Normal Form (1NF)

Definition

A table is in First Normal Form when every column contains only a single value and each record is unique.

Example

User Table

- User ID
- Full Name
- Email
- Department

Each field stores only one value.

Benefits

- Removes repeating groups
- Improves data organization
- Makes searching easier

---

# Second Normal Form (2NF)

Definition

A table is in Second Normal Form when it satisfies First Normal Form and all non-key attributes depend completely on the Primary Key.

Example

Case Table

- Case ID
- Case Title
- Investigator Name

All information depends on the Case ID.

Benefits

- Removes partial dependency
- Reduces duplicate information
- Improves consistency

---

# Third Normal Form (3NF)

Definition

A table is in Third Normal Form when it satisfies Second Normal Form and contains no transitive dependency.

Example

Instead of storing Department Name repeatedly in multiple tables, it can be stored separately and linked through a key.

Benefits

- Eliminates redundant data
- Improves database efficiency
- Simplifies future maintenance

---

## Advantages of Normalization

- Reduces Data Redundancy
- Improves Data Integrity
- Faster Database Operations
- Better Data Security
- Easier Database Maintenance
- Supports Large Scale Applications

---

## Conclusion

Normalization is an important part of database design. It improves performance, reduces duplication, and ensures reliable storage of cyber crime investigation data in the AIDEX system.