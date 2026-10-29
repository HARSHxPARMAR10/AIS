# Dashboard Navigation

Login
 ↓
Dashboard
 ↓
Cases
 ↓
Evidence
 ↓
Reports
 ↓
Logout

# AIDEX Dashboard Navigation Design

## 1. Introduction

Dashboard Navigation defines how users move between different modules of the AIDEX system.

The navigation system must be simple, secure and role-based.

Every user will see only those menu options that are allowed for their assigned role.

The system supports the following roles:

- Administrator
- Investigator
- Cyber Officer

---

## 2. Main Navigation Flow

```text
Login Page
    ↓
Authentication
    ↓
Role Verification
    ↓
Dashboard
    ↓
Cases
    ↓
Evidence
    ↓
Reports
    ↓
Profile
    ↓
Logout

## Login Navigation Flow

Open AIDEX Login Page
        ↓
Enter Username and Password
        ↓
Validate Credentials
        ↓
Check Account Status
        ↓
Verify User Role
        ↓
Create User Session
        ↓
Redirect to Role-Based Dashboard

## Administrator Navigation Flow

Administrator Login
        ↓
Administrator Dashboard
        ↓
Manage Users
        ↓
Approve or Reject Accounts
        ↓
Manage Cases
        ↓
View Evidence
        ↓
Review Reports
        ↓
View Audit Logs
        ↓
System Settings
        ↓
Logout

Administrator Menu Options
Dashboard
Manage Users
Pending Account Approvals
Cases
Evidence
Reports
Audit Logs
Security Settings
Profile
Logout
Administrator Navigation Purpose
The Administrator can access management and monitoring sections of the system.
The Administrator can:
Approve new users
Change user roles
Activate or suspend accounts
View all cases
Review evidence records
View reports
Monitor audit logs
Change system settings

## Investigator Navigation Flow

Investigator Login
        ↓
Investigator Dashboard
        ↓
Assigned Cases
        ↓
Create or Update Case
        ↓
Upload Evidence
        ↓
View Investigation Progress
        ↓
Generate Investigation Report
        ↓
Profile
        ↓
Logout

Investigator Menu Options
Dashboard
Assigned Cases
Create Case
Evidence Upload
Evidence List
Investigation Progress
Reports
Notifications
Profile
Logout
Investigator Navigation Purpose
The Investigator uses the system to manage cyber crime investigation work.
The Investigator can:
View assigned cases
Create new cases when authorized
Update case information
Upload evidence
Track investigation progress
Generate investigation reports
View own activity history

## Cyber Officer Navigation Flow

Cyber Officer Login
        ↓
Cyber Officer Dashboard
        ↓
Assigned Review Cases
        ↓
Evidence Verification
        ↓
AI Analysis Review
        ↓
Add Technical Findings
        ↓
Generate Technical Report
        ↓
Profile
        ↓
Logout

Cyber Officer Menu Options
Dashboard
Review Cases
Evidence Verification
AI Analysis
Technical Findings
Security Alerts
Technical Reports
Profile
Logout
Cyber Officer Navigation Purpose
The Cyber Officer performs technical review and evidence verification.
The Cyber Officer can:
View assigned cases
Verify evidence metadata
Review SHA-256 hash information
Check OCR results
Review AI analysis
Add technical findings
Generate technical reports

## Sidebar Navigation

Dashboard
Cases
Evidence
Reports
AI Analysis
Users
Profile
Settings
Logout

Role-Based Sidebar Rule
Not every role will see every menu item.
Example:
Administrator can see Users and Settings.
Investigator can see Assigned Cases and Evidence Upload.
Cyber Officer can see Evidence Verification and AI Analysis.
Unauthorized menu items must remain hidden.
Backend permission checks must still be applied.

## Navbar Navigation

The Navbar is displayed at the top of the dashboard.
It provides quick access to:
AIDEX Logo
Search
Notifications
Profile Image
Username
User Role
Logout
Navbar Functions
Search records
View notifications
Open profile menu
Display current role
Logout securely

## Dashboard card navigation

Dashboard cards may also act as navigation shortcuts.
Examples:
Total Cases card opens Cases List.
Pending Evidence card opens Evidence Verification.
Total Reports card opens Reports Page.
Active Users card opens User Management.
Security Alerts card opens Audit or Security Logs.

## Quick Action Navigation

Quick Action buttons help users access frequently used functions.
Examples:
Create New Case
Upload Evidence
Verify Evidence
Generate Report
View AI Analysis
Approve User
View Audit Logs

## Search Navigation 

The Search Bar can be used to find:
Case ID
Case Number
Case Title
Evidence ID
Evidence Type
Username
Badge ID
Report ID
After search, the user is redirected to the appropriate result page.

## Notification Navigation

Notifications should link users to relevant pages.

## Navigation Security Rules


Users must login before dashboard access.
Role permissions must be checked on every protected page.
Unauthorized users cannot open restricted pages.
Suspended and deactivated accounts cannot access the dashboard.
Direct URL access must also be validated.
Logout must securely terminate the user session.

## Unauthorized Flow

Restricted URL
    ↓
Permission Check
    ↓
Access Denied
    ↓
Redirect to Authorized Dashboard

## logout flow

Click Logout
    ↓
Terminate Session
    ↓
Clear Authentication Data
    ↓
Redirect to Login Page

## expected result 

```markdown
# AIDEX Responsive Dashboard Design

## Introduction

Responsive Design ensures that the AIDEX dashboard works properly on different screen sizes.

The dashboard should support:

- Desktop Computers
- Laptops
- Tablets
- Mobile Phones

## Desktop Layout

Desktop Layout Features:

- Full Sidebar visible
- Full Navbar visible
- Four cards in one row
- Large tables
- Complete charts
- Search bar visible
- Profile details visible

Recommended Width:

```text
1200 pixels and above