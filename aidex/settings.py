"""
Django settings for the AIDEX project.

AIDEX:
AI Digital Evidence Intelligence & Investigation System

Environment configuration is loaded from the .env file.
"""

import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

from dotenv import load_dotenv


# ==========================================================
# Base Directory
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ==========================================================
# Environment Variables
# ==========================================================

load_dotenv(
    dotenv_path=BASE_DIR / ".env",
)


def get_env_bool(
    variable_name: str,
    default: bool = False,
) -> bool:
    """
    Convert an environment variable into a boolean value.
    """

    value = os.getenv(
        variable_name,
        str(default),
    )

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_env_list(
    variable_name: str,
    default: str = "",
) -> list[str]:
    """
    Convert a comma-separated environment variable into a list.
    """

    value = os.getenv(
        variable_name,
        default,
    )

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def get_env_int(
    variable_name: str,
    default: int,
    *,
    minimum: int | None = None,
) -> int:
    """
    Read an integer environment variable safely.

    Invalid values fall back to the supplied default instead of preventing
    Django from starting.
    """

    raw_value = os.getenv(
        variable_name,
        str(default),
    )

    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        value = default

    if minimum is not None:
        value = max(minimum, value)

    return value


# ==========================================================
# Core Application Configuration
# ==========================================================

APP_NAME = os.getenv(
    "APP_NAME",
    "AIDEX",
)

APP_ENV = os.getenv(
    "APP_ENV",
    "development",
)

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "django-insecure-development-only-change-this-key",
)

DEBUG = get_env_bool(
    "DEBUG",
    True,
)

IS_PRODUCTION = (
    APP_ENV.strip().lower() == "production"
    or not DEBUG
)

if IS_PRODUCTION and (
    len(SECRET_KEY) < 50
    or len(set(SECRET_KEY)) < 5
    or SECRET_KEY.startswith("django-insecure-")
):
    raise RuntimeError(
        (
            "A strong, random SECRET_KEY of at least 50 characters must be "
            "configured when AIDEX runs in production."
        )
    )

ALLOWED_HOSTS = get_env_list(
    "ALLOWED_HOSTS",
    "127.0.0.1,localhost",
)

# Render provides the public hostname at runtime.  Adding it here keeps the
# deployment configuration secret-free while retaining an explicit host list
# on every other platform.
RENDER_EXTERNAL_HOSTNAME = os.getenv("RENDER_EXTERNAL_HOSTNAME", "").strip()
if RENDER_EXTERNAL_HOSTNAME and RENDER_EXTERNAL_HOSTNAME not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)


# ==========================================================
# Installed Applications
# ==========================================================

INSTALLED_APPS = [
    # Django applications
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # AIDEX applications
    "accounts",
    "dashboard",
    "cases",
    "evidence",
    "reports",
    "ai_engine",
]


# ==========================================================
# Middleware
# ==========================================================

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# WhiteNoise serves versioned static assets when AIDEX runs behind Gunicorn.
# Development keeps Django's normal static-file behaviour.
if IS_PRODUCTION:
    MIDDLEWARE.insert(
        1,
        "whitenoise.middleware.WhiteNoiseMiddleware",
    )


# ==========================================================
# URL and Application Configuration
# ==========================================================

ROOT_URLCONF = "aidex.urls"

WSGI_APPLICATION = "aidex.wsgi.application"

ASGI_APPLICATION = "aidex.asgi.application"


# ==========================================================
# Templates
# ==========================================================

TEMPLATES = [
    {
        "BACKEND": (
            "django.template.backends.django.DjangoTemplates"
        ),
        "DIRS": [
            BASE_DIR / "templates",
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                (
                    "django.template.context_processors.request"
                ),
                (
                    "django.contrib.auth.context_processors.auth"
                ),
                (
                    "django.contrib.messages.context_processors.messages"
                ),
            ],
        },
    },
]


# ==========================================================
# Database
# ==========================================================

DATABASE_ENGINE = os.getenv(
    "DB_ENGINE",
    "sqlite",
).strip().lower()

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

if DATABASE_URL:
    parsed_database_url = urlsplit(DATABASE_URL)
    if parsed_database_url.scheme not in {"postgres", "postgresql"}:
        raise RuntimeError("DATABASE_URL must use the postgres or postgresql scheme.")
    if not parsed_database_url.hostname:
        raise RuntimeError("DATABASE_URL must contain a database host.")

    database_name = unquote(parsed_database_url.path.lstrip("/"))
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": database_name,
            "USER": unquote(parsed_database_url.username or ""),
            "PASSWORD": unquote(parsed_database_url.password or ""),
            "HOST": parsed_database_url.hostname,
            "PORT": parsed_database_url.port or "5432",
            "CONN_MAX_AGE": get_env_int("DB_CONN_MAX_AGE", 60, minimum=0),
            "OPTIONS": {
                "sslmode": os.getenv("DB_SSLMODE", "require"),
            },
        }
    }
elif DATABASE_ENGINE == "mysql":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "NAME": os.getenv("DB_NAME", "aidex"),
            "USER": os.getenv("DB_USER", "aidex"),
            "PASSWORD": os.getenv("DB_PASSWORD", ""),
            "HOST": os.getenv("DB_HOST", "127.0.0.1"),
            "PORT": os.getenv("DB_PORT", "3306"),
            "CONN_MAX_AGE": get_env_int(
                "DB_CONN_MAX_AGE",
                60,
                minimum=0,
            ),
            "OPTIONS": {
                "charset": "utf8mb4",
            },
        }
    }
elif DATABASE_ENGINE == "postgresql" or DATABASE_ENGINE == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("DB_NAME", "postgres"),
            "USER": os.getenv("DB_USER", "postgres"),
            "PASSWORD": os.getenv("DB_PASSWORD", ""),
            "HOST": os.getenv("DB_HOST", "127.0.0.1"),
            "PORT": os.getenv("DB_PORT", "5432"),
            "CONN_MAX_AGE": get_env_int("DB_CONN_MAX_AGE", 60, minimum=0),
            "OPTIONS": {
                "sslmode": os.getenv("DB_SSLMODE", "require"),
            },
        }
    }
elif DATABASE_ENGINE == "sqlite":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
else:
    raise RuntimeError(
        "DB_ENGINE must be 'sqlite', 'mysql', or 'postgresql'."
    )


# ==========================================================
# Custom User Model
# ==========================================================

AUTH_USER_MODEL = "accounts.User"


# ==========================================================
# Authentication Redirects
# ==========================================================

LOGIN_URL = "accounts:login"

LOGIN_REDIRECT_URL = "accounts:dashboard_redirect"

LOGOUT_REDIRECT_URL = "accounts:login"


# ==========================================================
# Password Validation
# ==========================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "MinimumLengthValidator"
        ),
        "OPTIONS": {
            "min_length": 8,
        },
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "CommonPasswordValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "NumericPasswordValidator"
        ),
    },
]


# ==========================================================
# Internationalization
# ==========================================================

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Asia/Kolkata"

USE_I18N = True

USE_TZ = True


# ==========================================================
# Static Files
# ==========================================================

STATIC_URL = "/static/"

STATIC_ROOT = BASE_DIR / "staticfiles"

STATICFILES_DIRS = [
    BASE_DIR / "static",
]


# ==========================================================
# Media Files
# ==========================================================

# Media is deliberately routed through aidex.media_views.protected_media.
# Never expose MEDIA_ROOT directly through a public web-server alias.
MEDIA_URL = "/protected-media/"

MEDIA_ROOT = BASE_DIR / "media"


# ==========================================================
# Default Primary Key
# ==========================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ==========================================================
# Session Configuration
# ==========================================================

SESSION_COOKIE_AGE = 60 * 60

SESSION_SAVE_EVERY_REQUEST = True

SESSION_EXPIRE_AT_BROWSER_CLOSE = False

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"


# ==========================================================
# CSRF Configuration
# ==========================================================

CSRF_COOKIE_HTTPONLY = False

CSRF_COOKIE_SAMESITE = "Lax"

CSRF_TRUSTED_ORIGINS = get_env_list(
    "CSRF_TRUSTED_ORIGINS",
    "",
)

if RENDER_EXTERNAL_HOSTNAME:
    render_origin = f"https://{RENDER_EXTERNAL_HOSTNAME}"
    if render_origin not in CSRF_TRUSTED_ORIGINS:
        CSRF_TRUSTED_ORIGINS.append(render_origin)


# ==========================================================
# Security Configuration
# ==========================================================

X_FRAME_OPTIONS = "DENY"

SECURE_CONTENT_TYPE_NOSNIFF = True

SECURE_REFERRER_POLICY = "same-origin"

SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"


# Enable these automatically when DEBUG=False.

SESSION_COOKIE_SECURE = IS_PRODUCTION

CSRF_COOKIE_SECURE = IS_PRODUCTION

SECURE_SSL_REDIRECT = get_env_bool(
    "SECURE_SSL_REDIRECT",
    IS_PRODUCTION,
)

SECURE_HSTS_SECONDS = get_env_int(
    "SECURE_HSTS_SECONDS",
    31_536_000 if IS_PRODUCTION else 0,
    minimum=0,
)

SECURE_HSTS_INCLUDE_SUBDOMAINS = get_env_bool(
    "SECURE_HSTS_INCLUDE_SUBDOMAINS",
    IS_PRODUCTION,
)

SECURE_HSTS_PRELOAD = get_env_bool(
    "SECURE_HSTS_PRELOAD",
    IS_PRODUCTION,
)

if get_env_bool("USE_X_FORWARDED_PROTO", False):
    SECURE_PROXY_SSL_HEADER = (
        "HTTP_X_FORWARDED_PROTO",
        "https",
    )


# ==========================================================
# Transactional Email and Password Reset Configuration
# ==========================================================

EMAIL_BACKEND = os.getenv(
    "EMAIL_BACKEND",
    "django.core.mail.backends.smtp.EmailBackend",
).strip()

EMAIL_HOST = os.getenv(
    "EMAIL_HOST",
    "smtp.gmail.com",
).strip()

EMAIL_PORT = get_env_int(
    "EMAIL_PORT",
    587,
    minimum=1,
)

EMAIL_USE_TLS = get_env_bool(
    "EMAIL_USE_TLS",
    True,
)

EMAIL_USE_SSL = get_env_bool(
    "EMAIL_USE_SSL",
    False,
)

if EMAIL_USE_TLS and EMAIL_USE_SSL:
    raise ValueError(
        "EMAIL_USE_TLS and EMAIL_USE_SSL cannot both be enabled."
    )

EMAIL_HOST_USER = os.getenv(
    "EMAIL_HOST_USER",
    "",
).strip()

EMAIL_HOST_PASSWORD = os.getenv(
    "EMAIL_HOST_PASSWORD",
    "",
).strip()

DEFAULT_FROM_EMAIL = os.getenv(
    "DEFAULT_FROM_EMAIL",
    EMAIL_HOST_USER,
).strip()

SERVER_EMAIL = os.getenv(
    "SERVER_EMAIL",
    DEFAULT_FROM_EMAIL,
).strip()

EMAIL_TIMEOUT = get_env_int(
    "EMAIL_TIMEOUT",
    20,
    minimum=1,
)

# Password-reset links remain valid for one hour by default.
PASSWORD_RESET_TIMEOUT = get_env_int(
    "PASSWORD_RESET_TIMEOUT",
    3600,
    minimum=300,
)


# Use hashed and compressed static assets in production. The static manifest
# also prevents accidentally serving stale frontend files after deployment.
if IS_PRODUCTION:
    STORAGES = {
        "default": {
            "BACKEND": (
                "django.core.files.storage.FileSystemStorage"
            ),
        },
        "staticfiles": {
            "BACKEND": (
                "whitenoise.storage."
                "CompressedManifestStaticFilesStorage"
            ),
        },
    }


# ==========================================================
# AIDEX AI Engine Configuration
# ==========================================================

AI_PROVIDER = os.getenv(
    "AI_PROVIDER",
    "GEMINI",
).strip().upper()

SUPPORTED_AI_PROVIDERS = {
    "GEMINI",
    "OPENROUTER",
    "LOCAL",
}

if AI_PROVIDER not in SUPPORTED_AI_PROVIDERS:
    raise ValueError(
        "AI_PROVIDER must be GEMINI, OPENROUTER, or LOCAL."
    )

_DEFAULT_AI_MODEL = (
    "openai/gpt-4o"
    if AI_PROVIDER == "OPENROUTER"
    else "local-forensic-demo-v1"
    if AI_PROVIDER == "LOCAL"
    else "gemini-flash-latest"
)

AI_MODEL = os.getenv(
    "AI_MODEL",
    _DEFAULT_AI_MODEL,
).strip()

# Preferred service-layer model setting. AI_MODEL remains supported for
# backward compatibility with the existing .env file.
AIDEX_GEMINI_MODEL = os.getenv(
    "AIDEX_GEMINI_MODEL",
    (
        AI_MODEL
        if AI_PROVIDER == "GEMINI"
        else "gemini-flash-latest"
    ),
).strip()

GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY",
    "",
).strip()

# OpenRouter uses an OpenAI-compatible server-side API. HTTP-Referer and
# X-Title are optional attribution headers; do not put the API key in either.
AIDEX_OPENROUTER_MODEL = os.getenv(
    "AIDEX_OPENROUTER_MODEL",
    (
        AI_MODEL
        if AI_PROVIDER == "OPENROUTER"
        else "openai/gpt-4o"
    ),
).strip()

OPENROUTER_API_KEY = os.getenv(
    "OPENROUTER_API_KEY",
    "",
).strip()

OPENROUTER_BASE_URL = os.getenv(
    "OPENROUTER_BASE_URL",
    "https://openrouter.ai/api/v1",
).strip().rstrip("/")

OPENROUTER_HTTP_REFERER = os.getenv(
    "OPENROUTER_HTTP_REFERER",
    "",
).strip()

OPENROUTER_APP_TITLE = os.getenv(
    "OPENROUTER_APP_TITLE",
    APP_NAME,
).strip()

AIDEX_OPENROUTER_MAX_MEDIA_BYTES = get_env_int(
    "AIDEX_OPENROUTER_MAX_MEDIA_BYTES",
    104_857_600,
    minimum=1,
)

AIDEX_OPENROUTER_PDF_ENGINE = os.getenv(
    "AIDEX_OPENROUTER_PDF_ENGINE",
    "cloudflare-ai",
).strip()

# Master switch for all fresh external AI-provider calls.
# Cached AIDEX results may still be read, but services.py will refuse to call
# Gemini or OpenRouter when this value is False.
ENABLE_AI = get_env_bool(
    "ENABLE_AI",
    True,
)

ENABLE_OCR = get_env_bool(
    "ENABLE_OCR",
    True,
)

ENABLE_HASHING = get_env_bool(
    "ENABLE_HASHING",
    True,
)

# Logical version of AIDEX's result-producing AI pipeline. Increase this when
# prompt construction, multimodal handling or normalization rules change so
# old results are not treated as compatible cache entries.
AIDEX_AI_PIPELINE_VERSION = os.getenv(
    "AIDEX_AI_PIPELINE_VERSION",
    "multimodal-v2",
).strip()

# Provider timeout is configured in seconds. services.py converts it to
# milliseconds only when constructing google-genai's HttpOptions.
#
# AIDEX_AI_TIMEOUT_SECONDS is the preferred variable. AI_API_TIMEOUT remains a
# compatibility fallback for the current project .env.
AIDEX_AI_TIMEOUT_SECONDS = get_env_int(
    "AIDEX_AI_TIMEOUT_SECONDS",
    get_env_int(
        "AI_API_TIMEOUT",
        60,
        minimum=1,
    ),
    minimum=1,
)

# Number of provider retries after the initial request.
# AIDEX_AI_MAX_RETRIES is preferred; AI_MAX_RETRY_COUNT remains compatible.
AIDEX_AI_MAX_RETRIES = get_env_int(
    "AIDEX_AI_MAX_RETRIES",
    get_env_int(
        "AI_MAX_RETRY_COUNT",
        3,
        minimum=0,
    ),
    minimum=0,
)
# Maximum output tokens requested from Gemini or OpenRouter.
AIDEX_AI_MAX_OUTPUT_TOKENS = get_env_int(
    "AIDEX_AI_MAX_OUTPUT_TOKENS",
    4096,
    minimum=256,
)

# Keep OpenRouter requests affordable on low-credit keys without reducing the
# richer Gemini response budget. Deployments with sufficient OpenRouter credit
# may override this provider-specific value explicitly.
AIDEX_OPENROUTER_MAX_OUTPUT_TOKENS = get_env_int(
    "AIDEX_OPENROUTER_MAX_OUTPUT_TOKENS",
    min(
        AIDEX_AI_MAX_OUTPUT_TOKENS,
        3072,
    ),
    minimum=256,
)

# Backward-compatible aliases used by older AIDEX code/configuration.
AI_API_TIMEOUT = AIDEX_AI_TIMEOUT_SECONDS
AI_MAX_RETRY_COUNT = AIDEX_AI_MAX_RETRIES
AI_MAX_OUTPUT_TOKENS = AIDEX_AI_MAX_OUTPUT_TOKENS


# ==========================================================
# OCR Configuration
# ==========================================================

OCR_LANGUAGE = os.getenv(
    "OCR_LANGUAGE",
    "eng",
)


# ==========================================================
# File Upload Configuration
# ==========================================================

FILE_UPLOAD_MAX_MEMORY_SIZE = get_env_int(
    "FILE_UPLOAD_MAX_MEMORY_SIZE",
    2_621_440,
    minimum=0,
)

DATA_UPLOAD_MAX_MEMORY_SIZE = get_env_int(
    "DATA_UPLOAD_MAX_MEMORY_SIZE",
    10_485_760,
    minimum=1,
)

# Evidence and report files should not be world-readable on a Unix host.
FILE_UPLOAD_PERMISSIONS = 0o600

FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o700

AIDEX_MAX_EVIDENCE_FILE_SIZE = get_env_int(
    "AIDEX_MAX_EVIDENCE_FILE_SIZE",
    104_857_600,
    minimum=1,
)

# AES-256-GCM master key for digital-evidence files.  This must be a URL-safe
# Base64 encoding of exactly 32 random bytes and must never be committed.
AIDEX_EVIDENCE_ENCRYPTION_KEY = os.getenv(
    "AIDEX_EVIDENCE_ENCRYPTION_KEY",
    "",
).strip()

# Keep False after legacy evidence has been migrated.  When True, old
# plaintext evidence can still be opened temporarily, and Django emits a
# security warning until the migration is completed.
AIDEX_EVIDENCE_ALLOW_LEGACY_PLAINTEXT = get_env_bool(
    "AIDEX_EVIDENCE_ALLOW_LEGACY_PLAINTEXT",
    False,
)

# OCR and some provider SDKs require a filesystem path.  AIDEX creates a
# permission-restricted plaintext file here only for the duration of that
# operation, then removes it.  Use an encrypted temporary volume in production.
AIDEX_EVIDENCE_TEMP_DIRECTORY = os.getenv(
    "AIDEX_EVIDENCE_TEMP_DIRECTORY",
    "",
).strip()


# ==========================================================
# Message Tags
# ==========================================================

from django.contrib.messages import constants as message_constants


MESSAGE_TAGS = {
    message_constants.DEBUG: "secondary",
    message_constants.INFO: "info",
    message_constants.SUCCESS: "success",
    message_constants.WARNING: "warning",
    message_constants.ERROR: "danger",
}


# ==========================================================
# Logging
# ==========================================================

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO",
)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "standard": {
            "format": (
                "{levelname} "
                "{asctime} "
                "{name} "
                "{message}"
            ),
            "style": "{",
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
    },

    "root": {
        "handlers": [
            "console",
        ],
        "level": LOG_LEVEL,
    },

    "loggers": {
        "django": {
            "handlers": [
                "console",
            ],
            "level": LOG_LEVEL,
            "propagate": False,
        },

        "ai_engine": {
            "handlers": [
                "console",
            ],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}
