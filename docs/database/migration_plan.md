# AIDEX Database Migration Plan

## Introduction

This document defines the migration process used to convert Django model changes into database tables and schema updates.

The migration plan ensures that the AIDEX database remains consistent, traceable and safe during development.

---

## Objectives

The main objectives of the migration plan are:

- Convert Django models into database tables
- Apply schema changes safely
- Maintain migration history
- Prevent inconsistent database states
- Verify relationships and constraints
- Support future database updates

---

## Applications Included

The following Django applications contain database models:

- accounts
- cases
- evidence
- reports

---

## Migration Workflow

```text
Review Django Models
        ↓
Run System Check
        ↓
Create Migration Files
        ↓
Review Generated Migrations
        ↓
Apply Database Migrations
        ↓
Verify Migration Status
        ↓
Test Database Models
```

---

## Step 1 – Review Django Models

Before creating migrations, review:

- Field names
- Field data types
- Required fields
- Default values
- Unique constraints
- Foreign key relationships
- Model indexes
- Custom permissions
- Database table names

Files to review:

```text
accounts/models.py
cases/models.py
evidence/models.py
reports/models.py
```

---

## Step 2 – Run Django System Check

Command:

```bash
py manage.py check
```

Expected Output:

```text
System check identified no issues (0 silenced).
```

The system check helps identify:

- Invalid model fields
- Incorrect relationships
- Missing applications
- Admin configuration errors
- URL configuration errors

---

## Step 3 – Create Migration Files

Commands:

```bash
py manage.py makemigrations accounts
py manage.py makemigrations cases
py manage.py makemigrations evidence
py manage.py makemigrations reports
```

Or create migrations for all applications:

```bash
py manage.py makemigrations
```

Migration files are stored inside:

```text
app_name/migrations/
```

Example:

```text
cases/migrations/0001_initial.py
evidence/migrations/0001_initial.py
reports/migrations/0001_initial.py
```

---

## Step 4 – Review Generated Migrations

Before applying migrations, verify:

- Correct model creation
- Correct database table name
- Correct foreign key references
- Correct indexes
- Correct constraints
- Correct default values
- Correct dependency order

Migration dependencies should follow this logical order:

```text
accounts
    ↓
cases
    ↓
evidence
    ↓
reports
```

---

## Step 5 – Apply Database Migrations

Command:

```bash
py manage.py migrate
```

This command applies all pending migrations to the database.

Expected Result:

```text
Applying accounts migrations... OK
Applying cases migrations... OK
Applying evidence migrations... OK
Applying reports migrations... OK
```

---

## Step 6 – Verify Migration Status

Command:

```bash
py manage.py showmigrations
```

Applied migrations should display:

```text
[X]
```

Example:

```text
accounts
 [X] 0001_initial

cases
 [X] 0001_initial

evidence
 [X] 0001_initial

reports
 [X] 0001_initial
```

---

## Step 7 – Verify Database Tables

Expected tables include:

```text
accounts_user
aidex_cases
aidex_evidence
aidex_investigation_reports
```

Additional Django tables may include:

```text
django_migrations
django_session
django_admin_log
auth_permission
django_content_type
```

---

## Step 8 – Test Model Relationships

The following relationships must be tested:

```text
User → Created Cases
User → Assigned Cases
Case → Evidence Items
User → Uploaded Evidence
User → Verified Evidence
Case → Investigation Reports
User → Generated Reports
User → Reviewed Reports
User → Approved Reports
```

---

## Step 9 – Create Test Records

Recommended test process:

1. Create a test User
2. Create a Case using that User
3. Assign an Investigator
4. Upload Evidence linked to the Case
5. Generate a Report linked to the Case
6. Verify all reverse relationships

---

## Step 10 – Run Final System Check

Command:

```bash
py manage.py check
```

Expected Output:

```text
System check identified no issues (0 silenced).
```

---

## Migration Safety Rules

- Never manually edit applied migration history.
- Do not delete migration files after team integration.
- Always commit migration files to Git.
- Run `git pull` before creating new migrations.
- Review migration conflicts before merging.
- Do not delete the production database.
- Create backups before major schema changes.
- Use descriptive migration names when required.

---

## Handling Migration Conflicts

If two branches create migrations for the same application:

1. Pull the latest `main` branch.
2. Merge or rebase the working branch.
3. Run:

```bash
py manage.py makemigrations --merge
```

4. Review the generated merge migration.
5. Run:

```bash
py manage.py migrate
```

6. Run system check.

---

## Development Database Reset Rule

Database reset should only be used during early development when no important data exists.

Before resetting:

- Stop the Django server
- Backup required test data
- Confirm migration files
- Inform the team

Never reset a database containing important investigation data.

---

## Migration Testing Checklist

- [ ] Models reviewed
- [ ] Applications added to `INSTALLED_APPS`
- [ ] System check passed
- [ ] Migration files generated
- [ ] Migration dependencies reviewed
- [ ] Migrations applied successfully
- [ ] Database tables verified
- [ ] Foreign keys tested
- [ ] Unique constraints tested
- [ ] Model creation tested
- [ ] Final system check passed

---

## Expected Result

The migration process should create and update AIDEX database tables safely while maintaining model relationships, constraints, indexes and migration history.