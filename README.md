# AIDEX

**AI Digital Evidence Intelligence & Investigation System**

AIDEX is a GTU Diploma minor project built with Django. It provides a
role-aware workflow for cyber-crime cases, digital evidence, SHA-256 integrity
verification, AES-256-GCM encryption at rest, AI-assisted forensic analysis,
and investigation reports.

## Main features

- Administrator, Investigator, and Cyber Officer roles
- Registration with administrator approval and login lockout protection
- Case assignment, status transitions, archive, and restore workflows
- Evidence upload with size, extension, content-signature, and type validation
- AES-256-GCM authenticated encryption for evidence files at rest
- SHA-256 evidence fingerprinting and tamper detection
- Protected evidence/report previews and downloads
- Explicit Gemini execution with retry limits, caching, and audit logs
- OCR and local text extraction
- Report drafting, review, approval, publication, revision, and audit history
- Responsive dashboards and search/filter pages

## Technology stack

- Python 3.12+
- Django 6
- SQLite for development; MySQL supported for deployment
- HTML, CSS, JavaScript, Bootstrap, and Chart.js
- Google Gemini through `google-genai`
- AES-256-GCM through `cryptography`
- Tesseract OCR, Pillow, OpenCV, and document parsers

## Windows setup

Open PowerShell in the project folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
$evidenceKey = python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
(Get-Content .env) -replace '^AIDEX_EVIDENCE_ENCRYPTION_KEY=.*$', "AIDEX_EVIDENCE_ENCRYPTION_KEY=$evidenceKey" | Set-Content .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Then open `http://127.0.0.1:8000/`.

Install Tesseract OCR separately and ensure `tesseract.exe` is available in
your system `PATH`. AI analysis can still process supported text/document files
when OCR is disabled.

## Environment configuration

Copy `.env.example` to `.env` and replace its placeholder values. Never commit
or share `.env`.

Important variables:

- `SECRET_KEY`: long random Django secret
- `DEBUG`: `True` locally; `False` when hosted
- `ALLOWED_HOSTS`: comma-separated hostnames
- `CSRF_TRUSTED_ORIGINS`: complete HTTPS origins when hosted
- `GEMINI_API_KEY`: Gemini API key
- `AI_MODEL`: enabled Gemini model name
- `DB_ENGINE`: `sqlite` or `mysql`
- `AIDEX_EVIDENCE_ENCRYPTION_KEY`: one permanent random 32-byte Base64 key
- `AIDEX_EVIDENCE_ALLOW_LEGACY_PLAINTEXT`: keep `False` after migration
- `AIDEX_EVIDENCE_TEMP_DIRECTORY`: optional encrypted temporary directory for OCR

The evidence encryption key is not a password. Back it up securely and never
commit or share it. Losing or changing this key makes previously encrypted
evidence unreadable.

Generate a production secret with:

```powershell
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

## Testing

```powershell
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test
python test_gemini.py
```

`test_gemini.py` makes a real provider request and may use free-tier quota.

## Upgrade an existing evidence library

Stop the Django server and back up the database, `media/` folder, and encryption
key. After adding `AIDEX_EVIDENCE_ENCRYPTION_KEY` to `.env`, run:

```powershell
python manage.py migrate
python manage.py encrypt_existing_evidence --dry-run
python manage.py encrypt_existing_evidence
python manage.py check
python manage.py test
```

The command encrypts legacy evidence atomically and verifies decrypted SHA-256
content before replacing each plaintext file. Already-encrypted files are
skipped, so the command is safe to run again. Keep the website stopped during
the actual migration so an upload cannot change while it is being encrypted.

## Production checklist

1. Set `APP_ENV=production`, `DEBUG=False`, and a strong `SECRET_KEY`.
2. Configure `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`.
3. Use HTTPS and set `USE_X_FORWARDED_PROTO=True` behind a trusted proxy.
4. Configure MySQL variables if MySQL is used.
5. Run `python manage.py collectstatic --noinput`.
6. Run `python manage.py check --deploy`.
7. Start with `gunicorn aidex.wsgi:application` on Linux hosting.
8. Keep `media/` private; never expose it as a public web-server directory.
9. Store `AIDEX_EVIDENCE_ENCRYPTION_KEY` in the host secret manager and backup
   it separately from encrypted evidence.
10. Use an encrypted temporary volume for OCR/provider materialization and use
    encrypted host backups as defence in depth.

## Safe GitHub/submission packaging

The `.gitignore` excludes `.env`, virtual environments, databases, media, and
cache files. After committing the intended source, create a clean ZIP with:

```powershell
git archive --format=zip --output=AIDEX_submission.zip HEAD
```

Do not ZIP the entire development folder because it may include secrets,
accounts, uploaded evidence, and the Windows virtual environment.

## Team

- Saksham Patel
- Harsh
- Shrushti
- Amisha
- Viral

## Project status

Version 1.2 — AES-256-GCM evidence-encryption build for the GTU Diploma minor
project.
