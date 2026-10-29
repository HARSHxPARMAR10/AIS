"""
AIDEX AI Engine Configuration

Central configuration for the AI Engine.

This project uses the Google Gemini Free API for AI-powered
digital evidence analysis.

Author:
AIDEX Development Team
"""

from pathlib import Path


# ==========================================================
# Project Configuration
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ==========================================================
# AI Provider Configuration
# ==========================================================

AI_PROVIDER = "GEMINI"

AI_MODEL = "gemini-flash-latest"

USE_FREE_GEMINI_API = True

ENABLE_AI = True

ENABLE_OCR = True

ENABLE_HASHING = True

ENABLE_METADATA_ANALYSIS = True

ENABLE_AI_LOGGING = True

ENABLE_FILE_VALIDATION = True


# ==========================================================
# Gemini API Configuration
# ==========================================================

GOOGLE_AI_STUDIO_URL = (
    "https://aistudio.google.com/"
)

GEMINI_API_BASE_URL = (
    "https://generativelanguage.googleapis.com/v1beta/"
)

API_TIMEOUT = 60

MAX_RETRY_COUNT = 3


# ==========================================================
# Model Configuration
# ==========================================================

DEFAULT_TEMPERATURE = 0.20

DEFAULT_TOP_P = 0.95

DEFAULT_TOP_K = 40

DEFAULT_MAX_OUTPUT_TOKENS = 2048


# ==========================================================
# File Upload Configuration
# ==========================================================

MAX_FILE_SIZE = 25 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = [
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".gif",
    ".webp",
]

ALLOWED_DOCUMENT_EXTENSIONS = [
    ".pdf",
    ".doc",
    ".docx",
    ".txt",
]

ALLOWED_VIDEO_EXTENSIONS = [
    ".mp4",
    ".avi",
    ".mov",
]

ALLOWED_AUDIO_EXTENSIONS = [
    ".wav",
    ".mp3",
]

SUPPORTED_EXTENSIONS = (
    ALLOWED_IMAGE_EXTENSIONS
    + ALLOWED_DOCUMENT_EXTENSIONS
    + ALLOWED_VIDEO_EXTENSIONS
    + ALLOWED_AUDIO_EXTENSIONS
)

ALLOW_EXECUTABLE_FILES = False


# ==========================================================
# Hash Configuration
# ==========================================================

DEFAULT_HASH_ALGORITHM = "SHA-256"

SUPPORTED_HASH_ALGORITHMS = [
    "SHA-256",
    "SHA-512",
]


# ==========================================================
# OCR Configuration
# ==========================================================

OCR_LANGUAGE = "eng"

OCR_CONFIDENCE_THRESHOLD = 0.70


# ==========================================================
# AI Report Configuration
# ==========================================================

REPORT_VERSION = "1.0"

MAX_SUMMARY_LENGTH = 1000

MAX_ANALYSIS_LENGTH = 3000


# ==========================================================
# Logging Configuration
# ==========================================================

LOG_LEVEL = "INFO"

LOG_AI_REQUESTS = True

LOG_AI_RESPONSES = False


# ==========================================================
# Security Configuration
# ==========================================================

VERIFY_FILE_HASH = True

VERIFY_FILE_EXTENSION = True

VERIFY_FILE_SIZE = True

VERIFY_FILE_METADATA = True


# ==========================================================
# Development Configuration
# ==========================================================

DEBUG_AI = True

USE_MOCK_PROVIDER = False

ENABLE_PROVIDER_FALLBACK = False