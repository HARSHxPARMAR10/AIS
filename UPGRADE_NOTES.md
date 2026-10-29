# AIDEX 1.2 AES Build — Replacement Instructions

This ZIP intentionally does not contain `.env`, `db.sqlite3`, `media/`, `.git/`,
or `.venv/`.

## Safest replacement method on Windows

1. Make one backup copy of your current AIDEX folder.
2. Extract this ZIP.
3. Copy the extracted `AIDEX_FIXED` files into your existing AIDEX project and
   allow Windows to replace matching source files.
4. Keep your existing `.env`, `db.sqlite3`, and `media/` folder.
5. Add a permanent AES-256 key to your existing `.env` without changing its
   other values:

```powershell
$evidenceKey = python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
Add-Content .env "`nAIDEX_EVIDENCE_ENCRYPTION_KEY=$evidenceKey"
Add-Content .env "AIDEX_EVIDENCE_ALLOW_LEGACY_PLAINTEXT=False"
```

If those variable names already exist, replace their values instead of adding
duplicates. Securely back up the generated key. Never change or lose it.

6. Stop the website, back up `db.sqlite3`, `media/`, and the AES key, then
   recreate or update the virtual environment and migrate:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py encrypt_existing_evidence --dry-run
python manage.py encrypt_existing_evidence
python manage.py check
python manage.py test
python manage.py runserver
```

If the old virtual environment gives package errors, delete only the project
`.venv` folder, create it again, and reinstall requirements. Do not delete
`.env`, `db.sqlite3`, or `media/` when preserving current configuration/data.

## Important production step

The existing `.env` was not changed. Before public hosting, change its
development values as described in `README.md`, then run:

```powershell
python manage.py collectstatic --noinput
python manage.py check --deploy
```

## Main fixes included

- Gemini model-detection script fixed
- Zero-retry configuration fixed
- MySQL, Gunicorn, WhiteNoise, and SOCKS dependencies added
- Production static/security configuration added
- Evidence content-signature validation added
- Renamed executable uploads blocked
- Dashboard and evidence regression coverage added
- Documentation and setup instructions rewritten
- Real AES-256-GCM authenticated evidence encryption added
- Existing plaintext evidence migration command added
- Wrong-key and ciphertext-tampering protection added
- AI/OCR temporary decryption cleanup added
- Sensitive/runtime files removed from the delivery ZIP
