# AIDEX Data Dictionary

## Introduction

The Data Dictionary describes all database tables, fields, data types and their purpose used in the AIDEX system.

---

# Users Table

| Field Name | Data Type | Required | Description |
|------------|-----------|----------|-------------|
| User_ID | Integer | Yes | Unique User Identifier |
| Full_Name | Varchar(100) | Yes | Full Name of User |
| Username | Varchar(50) | Yes | Login Username |
| Email | Varchar(100) | Yes | User Email Address |
| Password | Varchar(255) | Yes | Encrypted Password |
| Phone | Varchar(20) | Yes | Contact Number |
| Department | Varchar(100) | Yes | Department Name |
| Badge_ID | Varchar(30) | Yes | Official Badge Number |
| Role | Varchar(30) | Yes | User Role |
| Status | Varchar(20) | Yes | Account Status |

---

# Cases Table

| Field Name | Data Type | Required | Description |
|------------|-----------|----------|-------------|
| Case_ID | Integer | Yes | Unique Case ID |
| Case_Title | Varchar(200) | Yes | Case Title |
| Description | Text | Yes | Case Description |
| Investigator_ID | Integer | Yes | Assigned Investigator |
| Status | Varchar(20) | Yes | Case Status |
| Created_Date | Date | Yes | Case Creation Date |

---

# Evidence Table

| Field Name | Data Type | Required | Description |
|------------|-----------|----------|-------------|
| Evidence_ID | Integer | Yes | Unique Evidence ID |
| Case_ID | Integer | Yes | Related Case |
| File_Name | Varchar(200) | Yes | Evidence File Name |
| File_Type | Varchar(50) | Yes | Evidence Type |
| Upload_Date | Date | Yes | Upload Date |

---

# Reports Table

| Field Name | Data Type | Required | Description |
|------------|-----------|----------|-------------|
| Report_ID | Integer | Yes | Report ID |
| Case_ID | Integer | Yes | Related Case |
| Report_Title | Varchar(200) | Yes | Report Title |
| Generated_Date | Date | Yes | Report Date |

---

# Audit Logs Table

| Field Name | Data Type | Required | Description |
|------------|-----------|----------|-------------|
| Log_ID | Integer | Yes | Log ID |
| User_ID | Integer | Yes | User Reference |
| Activity | Text | Yes | User Activity |
| Log_Time | DateTime | Yes | Activity Time |

---

## Expected Result

The data dictionary provides complete information about every table and field used in the AIDEX database.