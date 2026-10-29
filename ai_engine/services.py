"""
AIDEX AI Engine Services
========================

Synchronous, auditable orchestration for AI-assisted forensic analysis.

Key guarantees
--------------
- Gemini or OpenRouter is called only from an explicit execution path.
- Evidence integrity is verified before execution.
- Supported images, PDFs, audio and video can be sent multimodally.
- Existing extracted text and bounded text files are still preferred where appropriate.
- Unsupported archives and office binaries are never sent directly.
- Provider output is requested as JSON and normalized defensively.
- Completed matching results can be reused without consuming provider quota.
- Every important lifecycle event is recorded in AIAnalysisLog.
- Configuration and SDK failures are converted into stable service errors.

Development:
    pip install google-genai openai

Environment:
    AI_PROVIDER=GEMINI  # or OPENROUTER
    GEMINI_API_KEY=...
    OPENROUTER_API_KEY=...
    AI_MODEL=gemini-flash-latest  # or openai/gpt-4o

Optional settings:
    AIDEX_GEMINI_MODEL
    AIDEX_OPENROUTER_MODEL
    OPENROUTER_BASE_URL
    OPENROUTER_HTTP_REFERER
    OPENROUTER_APP_TITLE
    AIDEX_AI_MAX_INPUT_CHARS
    AIDEX_AI_MAX_TEXT_FILE_BYTES
    AIDEX_AI_MAX_OUTPUT_TOKENS
    AIDEX_OPENROUTER_MAX_OUTPUT_TOKENS
    AIDEX_AI_TEMPERATURE
    AIDEX_AI_MAX_RETRIES
    AIDEX_AI_RETRY_BASE_SECONDS
    AIDEX_AI_TIMEOUT_SECONDS
    AIDEX_AI_STORED_INPUT_SUMMARY_CHARS
    AIDEX_AI_STORED_PROMPT_CHARS
    AIDEX_AI_PIPELINE_VERSION
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from django.conf import settings
from django.db import models, transaction
from django.db.models import Case, IntegerField, Value, When
from django.utils import timezone

from evidence.encrypted_storage import (
    decrypted_temporary_path,
    materialize_decrypted_file,
    remove_temporary_plaintext,
)

from .models import AIAnalysis, AIAnalysisLog
from .ocr import (
    OCRServiceError,
    extract_evidence_content,
)
from .prompts import (
    PROMPT_LIBRARY_REVISION,
    PromptError,
    build_prompt_for_analysis,
    get_system_instruction as get_prompt_system_instruction,
)


logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

DEFAULT_GEMINI_MODEL = "gemini-flash-latest"
DEFAULT_OPENROUTER_MODEL = "openai/gpt-4o"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
SUPPORTED_AI_PROVIDERS = {
    "GEMINI",
    "OPENROUTER",
    "LOCAL",
}
DEFAULT_PIPELINE_VERSION = "schema-fallback-json-v7"
DEFAULT_MAX_INPUT_CHARS = 50_000
DEFAULT_MAX_TEXT_FILE_BYTES = 2_000_000
DEFAULT_MAX_INLINE_MEDIA_BYTES = 18_000_000
DEFAULT_MAX_UPLOAD_MEDIA_BYTES = 100_000_000
DEFAULT_FILE_PROCESSING_TIMEOUT_SECONDS = 180
DEFAULT_FILE_POLL_SECONDS = 2.0
DEFAULT_MAX_OUTPUT_TOKENS = 4_096
DEFAULT_OPENROUTER_MAX_OUTPUT_TOKENS = 3_072
DEFAULT_TEMPERATURE = 0.2
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BASE_SECONDS = 2.0
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_STORED_INPUT_SUMMARY_CHARS = 10_000
DEFAULT_STORED_PROMPT_CHARS = 20_000

MAX_ERROR_LENGTH = 8_000
MAX_LOG_METADATA_TEXT = 2_000

TEXT_EXTENSIONS = {
    "txt",
    "csv",
    "log",
    "json",
    "xml",
    "md",
    "eml",
}

DOCUMENT_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
}

IMAGE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "webp",
    "gif",
    "bmp",
    "tiff",
}

VIDEO_EXTENSIONS = {
    "mp4",
    "mov",
    "avi",
    "mkv",
    "wmv",
    "flv",
    "webm",
    "m4v",
}

AUDIO_EXTENSIONS = {
    "mp3",
    "wav",
    "aac",
    "ogg",
    "flac",
    "m4a",
}

ARCHIVE_EXTENSIONS = {
    "zip",
    "rar",
    "7z",
}


# ============================================================================
# Exceptions
# ============================================================================

class AIServiceError(Exception):
    """Base error for the AIDEX AI service layer."""


class AIConfigurationError(AIServiceError):
    """Raised when provider configuration is missing or invalid."""


class AIProviderUnavailableError(AIServiceError):
    """Raised when the provider SDK or remote service is unavailable."""


class AIProviderQuotaError(AIServiceError):
    """Raised when quota or rate limits prevent execution."""


class AIProviderTimeoutError(AIServiceError):
    """Raised when a provider request times out."""


class AIProviderResponseError(AIServiceError):
    """Raised when provider output cannot be parsed or validated."""


class AIAnalysisStateError(AIServiceError):
    """Raised when execution is invalid for the current analysis state."""


class AIEvidenceIntegrityError(AIServiceError):
    """Raised when evidence integrity checks fail."""


class AIInputPreparationError(AIServiceError):
    """Raised when no safe provider input can be prepared."""


# ============================================================================
# Data Transfer Objects
# ============================================================================

@dataclass(slots=True)
class PreparedEvidenceInput:
    """
    Safe evidence representation supplied to the configured provider.

    media_path is populated only for supported local evidence files.
    """

    text: str
    source_kind: str
    mime_type: str = ""
    media_path: str = ""
    media_size_bytes: int = 0
    use_file_api: bool = False
    temporary_media_path: bool = False
    original_characters: int = 0
    submitted_characters: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)
    local_extraction_used: bool = False
    local_extractor_name: str = ""
    local_extraction_warning_count: int = 0
    local_extraction_truncated: bool = False
    local_extraction_confidence: float | None = None

    @property
    def has_media(self) -> bool:
        return bool(
            self.media_path
            and os.path.isfile(self.media_path)
        )

    def as_metadata(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "mime_type": self.mime_type,
            "media_attached": self.has_media,
            "media_size_bytes": self.media_size_bytes,
            "use_file_api": self.use_file_api,
            "original_characters": self.original_characters,
            "submitted_characters": self.submitted_characters,
            "truncated": self.truncated,
            "notes": self.notes,
            "local_extraction_used": self.local_extraction_used,
            "local_extractor_name": self.local_extractor_name,
            "local_extraction_warning_count": (
                self.local_extraction_warning_count
            ),
            "local_extraction_truncated": (
                self.local_extraction_truncated
            ),
            "local_extraction_confidence": (
                self.local_extraction_confidence
            ),
        }

    def cleanup(self) -> None:
        """Remove decrypted media materialized for the provider call."""

        if self.temporary_media_path and self.media_path:
            remove_temporary_plaintext(
                self.media_path
            )
            self.media_path = ""
            self.temporary_media_path = False


@dataclass(slots=True)
class TokenUsage:
    """Normalized provider token usage."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(slots=True)
class NormalizedAnalysisResult:
    """Validated provider result ready to persist."""

    summary: str
    confidence_score: Decimal | None
    risk_score: Decimal | None
    threat_level: str
    extracted_text: str
    keywords: list[str]
    entities: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    recommendations: str
    raw_response: dict[str, Any]
    token_usage: TokenUsage


@dataclass(slots=True)
class ExecutionOutcome:
    """Result returned by an explicit analysis execution."""

    analysis: AIAnalysis
    completed: bool
    cached: bool = False
    provider_called: bool = False
    error: str = ""


# ============================================================================
# Settings
# ============================================================================

def get_setting(name: str, default: Any = None) -> Any:
    return getattr(settings, name, default)


def get_positive_int_setting(name: str, default: int) -> int:
    raw_value = get_setting(name, default)

    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return default

    return value if value > 0 else default


def get_non_negative_int_setting(name: str, default: int) -> int:
    """Read an integer setting where zero is a meaningful valid value."""

    raw_value = get_setting(name, default)

    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return default

    return value if value >= 0 else default


def get_positive_float_setting(name: str, default: float) -> float:
    raw_value = get_setting(name, default)

    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return default

    return value if value > 0 else default


def is_ai_enabled() -> bool:
    """
    Return whether fresh external AI-provider calls are enabled.
    """

    raw_value = get_setting(
        "ENABLE_AI",
        True,
    )

    if isinstance(raw_value, bool):
        return raw_value

    return str(raw_value).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def ensure_ai_enabled() -> None:
    """
    Refuse all fresh provider calls when the AIDEX AI master switch is off.
    """

    if not is_ai_enabled():
        raise AIConfigurationError(
            "AI execution is disabled by the ENABLE_AI setting."
        )


def get_ai_provider_name() -> str:
    """Return and validate the configured AIDEX AI provider."""

    provider_name = str(
        get_setting("AI_PROVIDER", "")
        or os.getenv("AI_PROVIDER", "")
        or "GEMINI"
    ).strip().upper()

    if provider_name not in SUPPORTED_AI_PROVIDERS:
        raise AIConfigurationError(
            "AI_PROVIDER must be GEMINI, OPENROUTER, or LOCAL."
        )

    return provider_name


def get_provider_display_name(
    provider_name: str | None = None,
) -> str:
    """Return a safe provider label for messages and audit logs."""

    active_provider = (
        str(provider_name or "").strip().upper()
        or get_ai_provider_name()
    )

    return {
        "GEMINI": "Gemini",
        "OPENROUTER": "OpenRouter",
        "LOCAL": "Local AI",
    }.get(active_provider, "AI provider")


def get_ai_timeout_seconds() -> int:
    """
    Return the configured provider request timeout in seconds.
    """

    return get_positive_int_setting(
        "AIDEX_AI_TIMEOUT_SECONDS",
        get_positive_int_setting(
            "AI_API_TIMEOUT",
            DEFAULT_TIMEOUT_SECONDS,
        ),
    )


def get_openrouter_max_output_tokens() -> int:
    """Return OpenRouter's independent, positive output-token budget."""

    generic_budget = get_positive_int_setting(
        "AIDEX_AI_MAX_OUTPUT_TOKENS",
        DEFAULT_MAX_OUTPUT_TOKENS,
    )

    return get_positive_int_setting(
        "AIDEX_OPENROUTER_MAX_OUTPUT_TOKENS",
        min(
            generic_budget,
            DEFAULT_OPENROUTER_MAX_OUTPUT_TOKENS,
        ),
    )


def get_gemini_api_key() -> str:
    """
    Read the API key from Django settings first, then the environment.

    The ENABLE_AI guard is checked before exposing provider configuration so
    a disabled AIDEX installation cannot accidentally create a Gemini client.
    """

    ensure_ai_enabled()

    api_key = str(
        get_setting("GEMINI_API_KEY", "")
        or os.getenv("GEMINI_API_KEY", "")
        or ""
    ).strip()

    if not api_key:
        raise AIConfigurationError(
            "GEMINI_API_KEY is not configured."
        )

    return api_key


def get_gemini_model_name() -> str:
    """
    Support both AIDEX_GEMINI_MODEL and the existing AI_MODEL setting.
    """

    return str(
        get_setting("AIDEX_GEMINI_MODEL", "")
        or get_setting("AI_MODEL", "")
        or os.getenv("AIDEX_GEMINI_MODEL", "")
        or os.getenv("AI_MODEL", "")
        or DEFAULT_GEMINI_MODEL
    ).strip()


def get_openrouter_api_key() -> str:
    """Return the server-side OpenRouter API key."""

    ensure_ai_enabled()

    api_key = str(
        get_setting("OPENROUTER_API_KEY", "")
        or os.getenv("OPENROUTER_API_KEY", "")
        or ""
    ).strip()

    if not api_key:
        raise AIConfigurationError(
            "OPENROUTER_API_KEY is not configured."
        )

    return api_key


def get_openrouter_model_name() -> str:
    """Return the configured OpenRouter model slug."""

    return str(
        get_setting("AIDEX_OPENROUTER_MODEL", "")
        or (
            get_setting("AI_MODEL", "")
            if get_ai_provider_name() == "OPENROUTER"
            else ""
        )
        or os.getenv("AIDEX_OPENROUTER_MODEL", "")
        or (
            os.getenv("AI_MODEL", "")
            if get_ai_provider_name() == "OPENROUTER"
            else ""
        )
        or DEFAULT_OPENROUTER_MODEL
    ).strip()


def get_openrouter_base_url() -> str:
    """Return a validated HTTPS OpenRouter-compatible base URL."""

    base_url = str(
        get_setting("OPENROUTER_BASE_URL", "")
        or os.getenv("OPENROUTER_BASE_URL", "")
        or DEFAULT_OPENROUTER_BASE_URL
    ).strip().rstrip("/")

    if not base_url.casefold().startswith("https://"):
        raise AIConfigurationError(
            "OPENROUTER_BASE_URL must use HTTPS."
        )

    return base_url


def get_openrouter_attribution_headers() -> dict[str, str]:
    """Build OpenRouter's optional application-attribution headers."""

    headers: dict[str, str] = {}
    referer = str(
        get_setting("OPENROUTER_HTTP_REFERER", "")
        or os.getenv("OPENROUTER_HTTP_REFERER", "")
        or ""
    ).strip()
    app_title = str(
        get_setting("OPENROUTER_APP_TITLE", "")
        or os.getenv("OPENROUTER_APP_TITLE", "")
        or get_setting("APP_NAME", "")
        or "AIDEX"
    ).strip()

    if referer:
        if not referer.casefold().startswith(("https://", "http://")):
            raise AIConfigurationError(
                "OPENROUTER_HTTP_REFERER must be an HTTP(S) URL."
            )

        headers["HTTP-Referer"] = referer

    if app_title:
        headers["X-OpenRouter-Title"] = truncate_text(
            app_title,
            200,
        )

    return headers


def get_configured_model_name(
    provider_name: str | None = None,
) -> str:
    """Return the selected provider's configured model name."""

    active_provider = (
        str(provider_name or "").strip().upper()
        or get_ai_provider_name()
    )

    if active_provider == "OPENROUTER":
        return get_openrouter_model_name()

    if active_provider == "GEMINI":
        return get_gemini_model_name()

    if active_provider == "LOCAL":
        return str(
            get_setting("AI_MODEL", "")
            or os.getenv("AI_MODEL", "")
            or "local-forensic-demo-v1"
        ).strip()

    raise AIConfigurationError(
        "AI_PROVIDER must be GEMINI, OPENROUTER, or LOCAL."
    )


def get_analysis_provider_name(
    analysis: AIAnalysis,
) -> str:
    """Return the provider selected and persisted for one analysis."""

    provider_name = str(
        getattr(analysis, "provider", "")
        or get_ai_provider_name()
    ).strip().upper()

    if provider_name not in SUPPORTED_AI_PROVIDERS:
        raise AIConfigurationError(
            "This analysis must use GEMINI, OPENROUTER, or LOCAL."
        )

    return provider_name


def get_ai_pipeline_version() -> str:
    """
    Return the logical AIDEX analysis-pipeline version.

    Increment this value whenever prompt construction, multimodal handling,
    normalization rules or other result-affecting pipeline behavior changes.
    That prevents results produced by an older pipeline from being reused as
    if they were generated by the current implementation.
    """

    return str(
        get_setting("AIDEX_AI_PIPELINE_VERSION", "")
        or os.getenv("AIDEX_AI_PIPELINE_VERSION", "")
        or DEFAULT_PIPELINE_VERSION
    ).strip()


# ============================================================================
# Generic Helpers
# ============================================================================

def truncate_text(value: Any, maximum_length: int) -> str:
    text = str(value or "")
    return text if len(text) <= maximum_length else text[:maximum_length]


def normalize_whitespace(value: Any) -> str:
    text = (
        str(value or "")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )

    lines = [
        re.sub(r"[ \t]+", " ", line).strip()
        for line in text.splitlines()
    ]

    normalized: list[str] = []
    previous_blank = False

    for line in lines:
        is_blank = not line

        if is_blank and previous_blank:
            continue

        normalized.append(line)
        previous_blank = is_blank

    return "\n".join(normalized).strip()


def safe_decimal_percentage(value: Any) -> Decimal | None:
    if value in {None, ""}:
        return None

    try:
        numeric_value = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None

    numeric_value = max(
        Decimal("0.00"),
        min(Decimal("100.00"), numeric_value),
    )

    return numeric_value.quantize(Decimal("0.01"))


def normalize_string_list(
    value: Any,
    *,
    maximum_items: int = 50,
    maximum_item_length: int = 200,
) -> list[str]:
    if isinstance(value, str):
        raw_items: Iterable[Any] = re.split(r"[,;\n]+", value)
    elif isinstance(value, Sequence) and not isinstance(
        value,
        (bytes, bytearray),
    ):
        raw_items = value
    else:
        raw_items = []

    normalized: list[str] = []
    seen: set[str] = set()

    for raw_item in raw_items:
        item = normalize_whitespace(raw_item)[:maximum_item_length]

        if not item:
            continue

        lookup = item.casefold()

        if lookup in seen:
            continue

        seen.add(lookup)
        normalized.append(item)

        if len(normalized) >= maximum_items:
            break

    return normalized


def normalize_mapping_list(
    value: Any,
    *,
    maximum_items: int = 100,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    normalized: list[dict[str, Any]] = []

    for raw_item in value:
        if isinstance(raw_item, Mapping):
            item = {
                str(key)[:100]: make_json_safe(item_value)
                for key, item_value in raw_item.items()
            }
        else:
            text = normalize_whitespace(raw_item)

            if not text:
                continue

            item = {"description": text[:1_000]}

        normalized.append(item)

        if len(normalized) >= maximum_items:
            break

    return normalized


def make_json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Decimal):
        return float(value)

    if isinstance(value, Mapping):
        return {
            str(key): make_json_safe(item_value)
            for key, item_value in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(item) for item in value]

    if hasattr(value, "model_dump"):
        try:
            return make_json_safe(value.model_dump())
        except Exception:
            pass

    if hasattr(value, "to_json_dict"):
        try:
            return make_json_safe(value.to_json_dict())
        except Exception:
            pass

    if hasattr(value, "__dict__"):
        try:
            return {
                key: make_json_safe(item_value)
                for key, item_value in vars(value).items()
                if not key.startswith("_")
            }
        except Exception:
            pass

    return truncate_text(repr(value), 2_000)


def get_analysis_response_json_schema() -> dict[str, Any]:
    """
    Return a deliberately shallow provider structured-output schema.

    Gemini documents that very large or deeply nested schemas may be rejected
    with INVALID_ARGUMENT. AIDEX therefore keeps the provider contract simple
    and converts string findings/entities into the richer database shape
    during normalization.
    """

    threat_values = [
        str(value)
        for value, _ in AIAnalysis.ThreatLevel.choices
    ]

    return {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": (
                    "Concise evidence-grounded forensic summary."
                ),
            },
            "confidence_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
            },
            "risk_score": {
                "type": "number",
                "minimum": 0,
                "maximum": 100,
            },
            "threat_level": {
                "type": "string",
                "enum": threat_values,
            },
            "extracted_text": {
                "type": "string",
            },
            "keywords": {
                "type": "array",
                "items": {
                    "type": "string",
                },
                "maxItems": 30,
            },
            "entities": {
                "type": "array",
                "items": {
                    "type": "string",
                },
                "maxItems": 30,
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "string",
                },
                "maxItems": 30,
            },
            "recommendations": {
                "type": "string",
            },
        },
        "required": [
            "summary",
            "threat_level",
            "extracted_text",
            "keywords",
            "entities",
            "findings",
            "recommendations",
        ],
    }


def is_invalid_argument_error(
    exc: Exception,
) -> bool:
    """
    Detect a provider request-shape rejection.

    A 400 INVALID_ARGUMENT happens before a usable model response is produced.
    """

    message = normalize_whitespace(
        str(exc)
    ).casefold()

    class_name = (
        exc.__class__.__name__
        .casefold()
    )

    status_code = getattr(exc, "status_code", None)

    return (
        status_code == 400
        or "invalid_argument" in message
        or "invalid argument" in message
        or "bad request" in message
        or "badrequest" in class_name
        or (
            "400" in message
            and (
                "clienterror" in class_name
                or "api" in class_name
            )
        )
    )


def build_json_compatibility_prompt(
    prompt: str,
) -> str:
    """
    Add a compact JSON contract when schema mode is unavailable.

    This fallback is used only after a provider rejects the machine-readable
    response schema. It avoids repeating the large prompt-library schema.
    """

    return (
        f"{prompt}\\n\\n"
        "OUTPUT COMPATIBILITY MODE\\n"
        "Return ONLY one valid JSON object. Do not use Markdown fences. "
        "Use exactly these keys: "
        "summary (string), confidence_score (number 0-100 or null), "
        "risk_score (number 0-100 or null), threat_level (string), "
        "extracted_text (string), keywords (array of strings), "
        "entities (array of short strings), findings (array of short strings), "
        "recommendations (string). Keep the response concise and close every "
        "JSON string, array and object."
    )


def strip_json_markdown_fence(value: str) -> str:
    """
    Remove a single surrounding Markdown JSON fence when a model adds one.
    """

    text = str(value or "").strip().lstrip("\ufeff")

    fenced_match = re.fullmatch(
        r"```(?:json|JSON)?\s*(.*?)\s*```",
        text,
        re.DOTALL,
    )

    if fenced_match:
        return fenced_match.group(1).strip()

    return text


def find_balanced_json_object(value: str) -> str:
    """
    Return the first balanced JSON object embedded in text.

    Braces inside JSON strings are ignored. This is safer than selecting from
    the first "{" to the last "}", which can accidentally swallow surrounding
    prose or multiple objects.
    """

    text = str(value or "")

    start_index = -1
    depth = 0
    in_string = False
    escaped = False

    for index, character in enumerate(text):
        if start_index < 0:
            if character == "{":
                start_index = index
                depth = 1
            continue

        if in_string:
            if escaped:
                escaped = False
                continue

            if character == "\\":
                escaped = True
                continue

            if character == '"':
                in_string = False

            continue

        if character == '"':
            in_string = True
            continue

        if character == "{":
            depth += 1
            continue

        if character == "}":
            depth -= 1

            if depth == 0:
                return text[start_index:index + 1]

    return ""


def remove_json_trailing_commas(value: str) -> str:
    """
    Remove commas immediately before } or ] while preserving JSON strings.

    This repairs one common harmless formatting defect without inventing
    missing values or closing truncated structures.
    """

    text = str(value or "")
    output: list[str] = []

    in_string = False
    escaped = False
    index = 0

    while index < len(text):
        character = text[index]

        if in_string:
            output.append(character)

            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False

            index += 1
            continue

        if character == '"':
            in_string = True
            output.append(character)
            index += 1
            continue

        if character == ",":
            lookahead = index + 1

            while (
                lookahead < len(text)
                and text[lookahead].isspace()
            ):
                lookahead += 1

            if (
                lookahead < len(text)
                and text[lookahead] in "}]"
            ):
                index += 1
                continue

        output.append(character)
        index += 1

    return "".join(output)


def load_json_object_candidate(
    candidate: str,
) -> dict[str, Any] | None:
    """
    Parse a JSON object using conservative local repairs only.
    """

    attempts = [
        candidate,
        remove_json_trailing_commas(candidate),
    ]

    seen: set[str] = set()

    for attempt in attempts:
        if attempt in seen:
            continue

        seen.add(attempt)

        for strict in (True, False):
            try:
                parsed = json.loads(
                    attempt,
                    strict=strict,
                )
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ):
                continue

            if isinstance(parsed, dict):
                return parsed

    return None


def extract_json_object(response_text: str) -> dict[str, Any]:
    """
    Parse one provider JSON object defensively.

    Safe repairs:
    - UTF-8 BOM removal
    - Markdown JSON fence removal
    - balanced-object extraction from harmless surrounding prose
    - trailing-comma removal
    - permissive handling of unescaped control characters

    The parser deliberately does not fabricate missing braces, quotes or
    values. A genuinely truncated response remains a provider-response error
    and may be retried by the bounded provider retry loop.
    """

    text = strip_json_markdown_fence(
        response_text
    )

    if not text:
        raise AIProviderResponseError(
            "The provider returned an empty response."
        )

    parsed = load_json_object_candidate(
        text
    )

    if parsed is not None:
        return parsed

    balanced_object = find_balanced_json_object(
        text
    )

    if balanced_object:
        parsed = load_json_object_candidate(
            balanced_object
        )

        if parsed is not None:
            return parsed

    if "{" not in text:
        raise AIProviderResponseError(
            "The provider response did not contain a JSON object."
        )

    raise AIProviderResponseError(
        "The provider response contained invalid or incomplete JSON."
    )


def get_response_parsed_object(
    response: Any,
) -> dict[str, Any] | None:
    """
    Return google-genai's SDK-parsed structured response when available.

    When a response schema is configured, recent google-genai releases expose
    the validated result through response.parsed. Using that object avoids
    reparsing JSON text that the SDK has already decoded.
    """

    parsed = getattr(
        response,
        "parsed",
        None,
    )

    if parsed is None:
        return None

    if isinstance(
        parsed,
        Mapping,
    ):
        return {
            str(key): make_json_safe(value)
            for key, value in parsed.items()
        }

    if hasattr(
        parsed,
        "model_dump",
    ):
        try:
            dumped = parsed.model_dump()

            if isinstance(
                dumped,
                Mapping,
            ):
                return {
                    str(key): make_json_safe(value)
                    for key, value in dumped.items()
                }
        except Exception:
            pass

    if hasattr(
        parsed,
        "to_json_dict",
    ):
        try:
            dumped = parsed.to_json_dict()

            if isinstance(
                dumped,
                Mapping,
            ):
                return {
                    str(key): make_json_safe(value)
                    for key, value in dumped.items()
                }
        except Exception:
            pass

    return None


def get_response_finish_reason(
    response: Any,
) -> str:
    """
    Return the first available provider finish-reason label.
    """

    for candidate in (
        getattr(
            response,
            "candidates",
            None,
        )
        or []
    ):
        finish_reason = getattr(
            candidate,
            "finish_reason",
            None,
        )

        if finish_reason is None:
            continue

        return str(
            getattr(
                finish_reason,
                "name",
                finish_reason,
            )
            or ""
        ).strip().upper()

    for choice in getattr(response, "choices", None) or []:
        finish_reason = getattr(choice, "finish_reason", None)

        if finish_reason:
            return str(finish_reason).strip().upper()

    return ""


def get_response_diagnostics(
    response: Any,
    response_text: str,
) -> dict[str, Any]:
    """
    Return non-content provider diagnostics safe for logs.
    """

    return {
        "finish_reason": get_response_finish_reason(
            response
        ),
        "response_characters": len(
            str(response_text or "")
        ),
        "provider_request_id": get_provider_request_id(
            response
        ),
    }


# ============================================================================
# Audit Logging
# ============================================================================

def create_analysis_log(
    analysis: AIAnalysis,
    event_type: str,
    message: str,
    *,
    actor: Any = None,
    metadata: Mapping[str, Any] | None = None,
    provider_request_id: str = "",
) -> AIAnalysisLog:
    return AIAnalysisLog.objects.create(
        analysis=analysis,
        event_type=event_type,
        message=truncate_text(
            normalize_whitespace(message),
            MAX_ERROR_LENGTH,
        ),
        actor=(
            actor
            if getattr(actor, "is_authenticated", False)
            else None
        ),
        provider=analysis.provider,
        provider_request_id=truncate_text(
            provider_request_id,
            150,
        ),
        metadata=make_json_safe(metadata or {}),
    )


# ============================================================================
# Evidence Input Preparation
# ============================================================================

def get_evidence_extension(analysis: AIAnalysis) -> str:
    explicit_extension = str(
        getattr(analysis.evidence, "file_extension", "") or ""
    ).strip().lower()

    if explicit_extension:
        return explicit_extension.lstrip(".")

    filename = str(
        getattr(analysis.evidence, "original_filename", "")
        or getattr(analysis.evidence, "filename", "")
        or ""
    )

    return Path(filename).suffix.lower().lstrip(".")


def get_evidence_mime_type(analysis: AIAnalysis) -> str:
    filename = str(
        getattr(analysis.evidence, "original_filename", "")
        or getattr(analysis.evidence, "filename", "")
        or ""
    )

    guessed_type, _ = mimetypes.guess_type(filename)
    return guessed_type or ""


def read_small_text_file(
    file_path: str,
    *,
    maximum_bytes: int,
) -> str:
    path = Path(file_path)

    with path.open("rb") as file_handle:
        raw_bytes = file_handle.read(maximum_bytes + 1)

    return raw_bytes[:maximum_bytes].decode(
        "utf-8",
        errors="replace",
    )


def build_evidence_metadata_text(analysis: AIAnalysis) -> str:
    evidence = analysis.evidence
    case = evidence.case

    original_filename = (
        getattr(evidence, "original_filename", "")
        or getattr(evidence, "filename", "")
        or "Unknown"
    )

    lines = [
        f"Analysis number: {analysis.analysis_number}",
        f"Analysis title: {analysis.title}",
        f"Analysis type: {analysis.get_analysis_type_display()}",
        f"Case number: {case.case_number}",
        f"Case title: {case.case_title}",
        f"Evidence title: {evidence.evidence_title}",
        f"Evidence type: {evidence.get_evidence_type_display()}",
        f"Original filename: {original_filename}",
        f"File extension: {get_evidence_extension(analysis) or 'unknown'}",
        f"File size bytes: {getattr(evidence, 'file_size', 0) or 0}",
        f"SHA-256: {getattr(evidence, 'sha256_hash', '') or 'Unavailable'}",
        (
            "Verification status: "
            f"{evidence.get_verification_status_display()}"
        ),
        (
            "Evidence description: "
            f"{normalize_whitespace(getattr(evidence, 'description', '')) or 'Not provided'}"
        ),
        (
            "Case description: "
            f"{normalize_whitespace(getattr(case, 'description', '')) or 'Not provided'}"
        ),
    ]

    return "\n".join(lines)


def should_use_local_extraction(
    analysis: AIAnalysis,
    extension: str,
) -> bool:
    """
    Decide whether AIDEX should derive text before a provider request.

    Text/structured/modern-office/archive formats benefit from local
    extraction because their original binary is not always sent externally.
    Image/video OCR is intentionally limited to OCR analysis requests so a
    normal multimodal review does not pay the local OCR cost unnecessarily.
    """

    if normalize_whitespace(
        getattr(
            analysis,
            "extracted_text",
            "",
        )
    ):
        return False

    if analysis.analysis_type in {
        AIAnalysis.AnalysisType.METADATA,
        AIAnalysis.AnalysisType.FILE_INTEGRITY,
    }:
        return False

    locally_preferred_extensions = (
        TEXT_EXTENSIONS
        | {
            "pdf",
            "docx",
            "xlsx",
            "pptx",
            "zip",
        }
    )

    if extension in locally_preferred_extensions:
        return True

    if (
        analysis.analysis_type == AIAnalysis.AnalysisType.OCR
        and (
            extension in IMAGE_EXTENSIONS
            or extension in VIDEO_EXTENSIONS
        )
    ):
        return True

    return False


def prepare_evidence_input(
    analysis: AIAnalysis,
) -> PreparedEvidenceInput:
    """
    Prepare bounded derived text plus optional supported original media.

    Local extraction from ai_engine.ocr is preferred where useful. Extraction
    failures are handled defensively:
    - image/video/PDF can still fall back to their supported original media;
    - unsupported office/archive binaries are not sent to a provider as
      metadata-only requests, avoiding low-value provider calls.
    """

    maximum_characters = get_positive_int_setting(
        "AIDEX_AI_MAX_INPUT_CHARS",
        DEFAULT_MAX_INPUT_CHARS,
    )

    maximum_text_file_bytes = get_positive_int_setting(
        "AIDEX_AI_MAX_TEXT_FILE_BYTES",
        DEFAULT_MAX_TEXT_FILE_BYTES,
    )

    maximum_inline_media_bytes = get_positive_int_setting(
        "AIDEX_AI_MAX_INLINE_MEDIA_BYTES",
        DEFAULT_MAX_INLINE_MEDIA_BYTES,
    )

    maximum_upload_media_bytes = get_positive_int_setting(
        "AIDEX_AI_MAX_UPLOAD_MEDIA_BYTES",
        DEFAULT_MAX_UPLOAD_MEDIA_BYTES,
    )

    notes: list[str] = []

    candidate_text = normalize_whitespace(
        getattr(
            analysis,
            "extracted_text",
            "",
        )
    )

    source_kind = (
        "stored_extracted_text"
        if candidate_text
        else "metadata_only"
    )

    local_extraction_used = False
    local_extractor_name = ""
    local_extraction_warning_count = 0
    local_extraction_truncated = False
    local_extraction_confidence: float | None = None
    local_extraction_error = ""

    media_path = ""
    media_size_bytes = 0
    use_file_api = False

    extension = get_evidence_extension(
        analysis
    )

    mime_type = get_evidence_mime_type(
        analysis
    )

    evidence_file = getattr(
        analysis.evidence,
        "evidence_file",
        None,
    )

    local_path = ""
    attach_original_media = False

    supported_media = (
        extension in IMAGE_EXTENSIONS
        or extension == "pdf"
        or extension in AUDIO_EXTENSIONS
        or extension in VIDEO_EXTENSIONS
    )

    if evidence_file is not None and getattr(
        evidence_file,
        "name",
        "",
    ):
        try:
            local_file_available = evidence_file.storage.exists(
                evidence_file.name
            )
        except (
            AttributeError,
            NotImplementedError,
            OSError,
            ValueError,
        ):
            local_file_available = False
    else:
        local_file_available = False

    if local_file_available:
        try:
            media_size_bytes = int(
                evidence_file.size
            )
        except (OSError, TypeError, ValueError):
            media_size_bytes = 0

    # Use the centralized local extraction layer before provider execution.
    # It performs no external AI calls.
    if (
        not candidate_text
        and local_file_available
        and should_use_local_extraction(
            analysis,
            extension,
        )
    ):
        try:
            extraction_result = extract_evidence_content(
                analysis.evidence
            )

            local_extraction_used = True
            local_extractor_name = (
                extraction_result.extractor_name
            )
            local_extraction_warning_count = (
                extraction_result.warning_count
            )
            local_extraction_truncated = (
                extraction_result.truncated
            )
            local_extraction_confidence = (
                extraction_result.confidence
            )

            extracted_candidate = normalize_whitespace(
                extraction_result.text
            )

            if extracted_candidate:
                candidate_text = extracted_candidate
                source_kind = (
                    f"local_{local_extractor_name}"
                )

                notes.append(
                    (
                        "Local evidence extraction completed before "
                        f"provider analysis using {local_extractor_name}."
                    )
                )
            else:
                notes.append(
                    (
                        "Local evidence extraction completed but produced "
                        "no readable text."
                    )
                )

            for warning in extraction_result.warnings[:10]:
                warning_message = normalize_whitespace(
                    warning.message
                )

                if warning_message:
                    notes.append(
                        f"Local extraction warning: {warning_message}"
                    )

        except OCRServiceError as exc:
            local_extraction_error = truncate_text(
                normalize_whitespace(
                    str(exc)
                )
                or exc.__class__.__name__,
                MAX_LOG_METADATA_TEXT,
            )

            notes.append(
                (
                    "Local evidence extraction was unavailable: "
                    f"{local_extraction_error}"
                )
            )

    # Simple bounded text fallback remains available if the dedicated
    # extractor could not produce text for a directly readable text file.
    if (
        not candidate_text
        and extension in TEXT_EXTENSIONS
        and local_file_available
    ):
        try:
            with decrypted_temporary_path(
                evidence_file,
                suffix=(
                    f".{extension}"
                    if extension
                    else ""
                ),
            ) as local_path:
                candidate_text = normalize_whitespace(
                    read_small_text_file(
                        local_path,
                        maximum_bytes=maximum_text_file_bytes,
                    )
                )

            if candidate_text:
                source_kind = "bounded_text_file_fallback"

                notes.append(
                    (
                        "Bounded plain-text fallback was used after local "
                        "extraction produced no usable text."
                    )
                )

        except OSError as exc:
            notes.append(
                "Text file could not be read locally: "
                f"{exc.__class__.__name__}."
            )

    if supported_media:
        if not local_file_available:
            notes.append(
                (
                    "The supported evidence file is not available on local "
                    "storage; metadata and extracted text will be used."
                )
            )

        elif media_size_bytes > maximum_upload_media_bytes:
            raise AIInputPreparationError(
                (
                    "Evidence file exceeds the configured multimodal "
                    "upload limit."
                )
            )

        else:
            attach_original_media = True

            if extension in IMAGE_EXTENSIONS:
                media_kind = "image_multimodal"
            elif extension == "pdf":
                media_kind = "pdf_multimodal"
            elif extension in AUDIO_EXTENSIONS:
                media_kind = "audio_multimodal"
            else:
                media_kind = "video_multimodal"

            source_kind = (
                f"{media_kind}_with_{source_kind}"
                if candidate_text
                else media_kind
            )

            use_file_api = (
                media_size_bytes > maximum_inline_media_bytes
                or extension == "pdf"
                or extension in AUDIO_EXTENSIONS
                or extension in VIDEO_EXTENSIONS
            )

            notes.append(
                (
                    "Original supported evidence media will be supplied to "
                    "the configured provider with metadata and derived text."
                )
            )

    elif extension in DOCUMENT_EXTENSIONS:
        # Modern office files should have been locally extracted. Legacy
        # binary formats are deliberately unsupported. Do not spend provider
        # quota on a metadata-only request for an unreadable binary.
        if not candidate_text:
            detail = (
                f" Local extraction error: {local_extraction_error}"
                if local_extraction_error
                else ""
            )

            raise AIInputPreparationError(
                (
                    f"No safe readable content could be extracted from "
                    f".{extension or 'unknown'} evidence. Convert the file "
                    "to PDF or a supported modern format before analysis."
                    f"{detail}"
                )
            )

        notes.append(
            (
                "Office-document binary was not sent directly; locally "
                "extracted text is used instead."
            )
        )

    elif extension in ARCHIVE_EXTENSIONS:
        if not candidate_text:
            detail = (
                f" Local extraction error: {local_extraction_error}"
                if local_extraction_error
                else ""
            )

            raise AIInputPreparationError(
                (
                    "No safe text-like archive content could be extracted. "
                    "The archive binary will not be sent to the provider."
                    f"{detail}"
                )
            )

        notes.append(
            (
                "Archive binary was not sent; only bounded, locally extracted "
                "text-like members are used."
            )
        )

    parts = [
        build_evidence_metadata_text(
            analysis
        ),
    ]

    if candidate_text:
        parts.extend([
            "",
            "DERIVED OR EXTRACTED EVIDENCE CONTENT:",
            candidate_text,
        ])

    elif not attach_original_media:
        notes.append(
            (
                "No extracted text or supported local media was available; "
                "analysis uses metadata only."
            )
        )

    combined_text = normalize_whitespace(
        "\n".join(
            parts
        )
    )

    original_characters = len(
        combined_text
    )

    truncated = (
        original_characters
        > maximum_characters
    )

    if truncated:
        combined_text = combined_text[
            :maximum_characters
        ]

        notes.append(
            (
                "Text input was truncated to the configured character "
                "limit."
            )
        )

    if not combined_text and not attach_original_media:
        raise AIInputPreparationError(
            "No safe provider input could be prepared."
        )

    if attach_original_media:
        try:
            media_path = materialize_decrypted_file(
                evidence_file,
                suffix=(
                    f".{extension}"
                    if extension
                    else ""
                ),
            )
        except (OSError, ValueError) as exc:
            raise AIInputPreparationError(
                "Evidence media could not be authenticated and decrypted."
            ) from exc

    return PreparedEvidenceInput(
        text=combined_text,
        source_kind=source_kind,
        mime_type=mime_type,
        media_path=media_path,
        media_size_bytes=media_size_bytes,
        use_file_api=use_file_api,
        temporary_media_path=bool(media_path),
        original_characters=original_characters,
        submitted_characters=len(
            combined_text
        ),
        truncated=truncated,
        notes=notes,
        local_extraction_used=local_extraction_used,
        local_extractor_name=local_extractor_name,
        local_extraction_warning_count=(
            local_extraction_warning_count
        ),
        local_extraction_truncated=(
            local_extraction_truncated
        ),
        local_extraction_confidence=(
            local_extraction_confidence
        ),
    )


# ============================================================================
# Prompt Construction
# ============================================================================

def get_system_instruction() -> str:
    """
    Return the centralized AIDEX system instruction from prompts.py.
    """

    return get_prompt_system_instruction()


def build_analysis_prompt(
    analysis: AIAnalysis,
    prepared_input: PreparedEvidenceInput,
) -> str:
    """
    Build the provider prompt through the centralized, versioned prompt
    library instead of maintaining a duplicate prompt implementation here.
    """

    media_context = prepared_input.as_metadata()

    additional_context = {
        "provider_input": media_context,
        "pipeline_version": get_ai_pipeline_version(),
        "prompt_library_revision": PROMPT_LIBRARY_REVISION,
    }

    try:
        prompt_result = build_prompt_for_analysis(
            analysis,
            evidence_text=prepared_input.text,
            custom_prompt=(
                analysis.request_prompt
                if analysis.analysis_type == AIAnalysis.AnalysisType.CUSTOM
                else ""
            ),
            additional_context=additional_context,
            media_context=media_context,
            maximum_context_characters=get_positive_int_setting(
                "AIDEX_AI_MAX_INPUT_CHARS",
                DEFAULT_MAX_INPUT_CHARS,
            ),
        )
    except PromptError as exc:
        raise AIInputPreparationError(
            f"Prompt construction failed: {exc}"
        ) from exc

    return prompt_result.prompt


# ============================================================================
# Provider Adapters
# ============================================================================

def import_google_genai():
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise AIProviderUnavailableError(
            "Google Gen AI SDK is not installed. "
            "Run: pip install google-genai"
        ) from exc

    return genai, types


def create_gemini_client():
    """
    Create a Gemini client with AIDEX's configured request timeout.

    google-genai HttpOptions.timeout is expressed in milliseconds, while the
    AIDEX setting is intentionally kept in seconds for easier configuration.
    """

    ensure_ai_enabled()

    genai, types = import_google_genai()

    timeout_milliseconds = (
        get_ai_timeout_seconds()
        * 1000
    )

    http_options = types.HttpOptions(
        timeout=timeout_milliseconds,
    )

    return genai.Client(
        api_key=get_gemini_api_key(),
        http_options=http_options,
    )


def get_response_text(response: Any) -> str:
    direct_text = getattr(response, "text", None)

    if direct_text:
        return str(direct_text)

    text_parts: list[str] = []

    for candidate in getattr(response, "candidates", None) or []:
        content = getattr(candidate, "content", None)

        for part in getattr(content, "parts", None) or []:
            part_text = getattr(part, "text", None)

            if part_text:
                text_parts.append(str(part_text))

    if text_parts:
        return "\n".join(text_parts).strip()

    for choice in getattr(response, "choices", None) or []:
        message = getattr(choice, "message", None)
        content = getattr(message, "content", None)

        if isinstance(content, str) and content:
            text_parts.append(content)
            continue

        for part in content or []:
            if isinstance(part, Mapping):
                part_text = part.get("text", "")
            else:
                part_text = getattr(part, "text", "")

            if part_text:
                text_parts.append(str(part_text))

    return "\n".join(text_parts).strip()


def get_provider_request_id(response: Any) -> str:
    for attribute_name in ("response_id", "request_id", "id"):
        value = getattr(response, attribute_name, None)

        if value:
            return truncate_text(value, 150)

    return ""


def extract_token_usage(response: Any) -> TokenUsage:
    usage = (
        getattr(response, "usage_metadata", None)
        or getattr(response, "usage", None)
    )

    if usage is None:
        return TokenUsage()

    raw_input = (
        getattr(usage, "prompt_token_count", None)
        or getattr(usage, "input_token_count", None)
        or getattr(usage, "prompt_tokens", None)
        or 0
    )

    raw_output = (
        getattr(usage, "candidates_token_count", None)
        or getattr(usage, "output_token_count", None)
        or getattr(usage, "completion_tokens", None)
        or 0
    )

    try:
        input_tokens = max(0, int(raw_input))
    except (TypeError, ValueError):
        input_tokens = 0

    try:
        output_tokens = max(0, int(raw_output))
    except (TypeError, ValueError):
        output_tokens = 0

    return TokenUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )


def redact_provider_secrets(value: Any) -> str:
    """Remove configured API keys and common bearer tokens from text."""

    message = normalize_whitespace(value)
    configured_secrets = {
        str(
            get_setting(setting_name, "")
            or os.getenv(setting_name, "")
            or ""
        ).strip()
        for setting_name in (
            "GEMINI_API_KEY",
            "OPENROUTER_API_KEY",
        )
    }

    for secret in configured_secrets:
        if secret:
            message = message.replace(secret, "[REDACTED]")

    message = re.sub(
        r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+",
        r"\1[REDACTED]",
        message,
    )
    message = re.sub(
        r"(?i)((?:api[_ -]?key|token)\s*[:=]\s*)[^\s,;]+",
        r"\1[REDACTED]",
        message,
    )
    message = re.sub(
        r"\bsk-(?:or-v1-|proj-)?[A-Za-z0-9_-]{12,}\b",
        "[REDACTED]",
        message,
    )

    return message


def classify_provider_exception(
    exc: Exception,
    *,
    provider_name: str | None = None,
) -> AIServiceError:
    message = redact_provider_secrets(exc)
    lowercase_message = message.casefold()
    class_name = exc.__class__.__name__.casefold()
    provider_label = get_provider_display_name(provider_name)

    quota_markers = (
        "quota",
        "rate limit",
        "insufficient credits",
        "payment required",
        "resource exhausted",
        "resourceexhausted",
        "402",
        "429",
        "too many requests",
    )

    timeout_markers = (
        "timeout",
        "timed out",
        "deadline exceeded",
        "deadlineexceeded",
    )

    authentication_markers = (
        "invalid api key",
        "incorrect api key",
        "authentication failed",
        "unauthorized",
        "401",
    )

    configuration_markers = (
        "model not found",
        "unknown model",
        "invalid model",
        "404",
    )

    if any(
        marker in lowercase_message or marker in class_name
        for marker in authentication_markers
    ):
        return AIConfigurationError(
            message or f"{provider_label} authentication failed."
        )

    if any(
        marker in lowercase_message or marker in class_name
        for marker in configuration_markers
    ):
        return AIConfigurationError(
            message or f"{provider_label} configuration is invalid."
        )

    if any(
        marker in lowercase_message or marker in class_name
        for marker in quota_markers
    ):
        return AIProviderQuotaError(
            message or f"{provider_label} quota or rate limit was exceeded."
        )

    if any(
        marker in lowercase_message or marker in class_name
        for marker in timeout_markers
    ):
        return AIProviderTimeoutError(
            message or f"{provider_label} request timed out."
        )

    return AIProviderUnavailableError(
        message or f"{provider_label} request failed."
    )


def _build_generation_config(
    types: Any,
    *,
    use_response_schema: bool = True,
) -> Any:
    """
    Build Gemini generation configuration.

    Preferred mode uses a shallow JSON schema. Compatibility mode retains
    application/json without a schema for API/model combinations that reject
    structured-schema arguments.
    """

    config_arguments: dict[str, Any] = {
        "system_instruction": get_system_instruction(),
        "temperature": float(
            get_setting(
                "AIDEX_AI_TEMPERATURE",
                0.1,
            )
            or 0.1
        ),
        "max_output_tokens": get_positive_int_setting(
            "AIDEX_AI_MAX_OUTPUT_TOKENS",
            DEFAULT_MAX_OUTPUT_TOKENS,
        ),
        "response_mime_type": "application/json",
    }

    if use_response_schema:
        config_arguments[
            "response_json_schema"
        ] = get_analysis_response_json_schema()

    return types.GenerateContentConfig(
        **config_arguments
    )


def wait_for_uploaded_file(
    client: Any,
    uploaded_file: Any,
) -> Any:
    """
    Wait until an uploaded media file is ready for model use.
    """

    timeout_seconds = get_positive_int_setting(
        "AIDEX_AI_FILE_PROCESSING_TIMEOUT_SECONDS",
        DEFAULT_FILE_PROCESSING_TIMEOUT_SECONDS,
    )

    poll_seconds = get_positive_float_setting(
        "AIDEX_AI_FILE_POLL_SECONDS",
        DEFAULT_FILE_POLL_SECONDS,
    )

    started = time.monotonic()
    current_file = uploaded_file

    while True:
        state = getattr(current_file, "state", None)
        state_name = str(
            getattr(state, "name", state) or ""
        ).strip().upper()

        if state_name in {"", "ACTIVE", "READY", "SUCCEEDED"}:
            return current_file

        if state_name in {"FAILED", "ERROR", "CANCELLED"}:
            raise AIProviderUnavailableError(
                f"Gemini file processing failed with state {state_name}."
            )

        if time.monotonic() - started > timeout_seconds:
            raise AIProviderTimeoutError(
                "Gemini file processing timed out."
            )

        time.sleep(poll_seconds)

        file_name = getattr(current_file, "name", "")

        if not file_name:
            return current_file

        current_file = client.files.get(name=file_name)


def delete_uploaded_file_safely(
    client: Any,
    uploaded_file: Any,
) -> None:
    """Best-effort cleanup for temporary Gemini Files API uploads."""

    file_name = getattr(uploaded_file, "name", "")

    if not file_name:
        return

    try:
        client.files.delete(name=file_name)
    except Exception:
        logger.warning(
            "Could not delete temporary Gemini file %s.",
            file_name,
            exc_info=True,
        )


def build_gemini_contents(
    *,
    client: Any,
    types: Any,
    prompt: str,
    prepared_input: PreparedEvidenceInput,
) -> tuple[list[Any], Any | None]:
    """
    Build text-only, inline-media or Files-API contents.
    """

    if not prepared_input.has_media:
        return [prompt], None

    if prepared_input.use_file_api:
        try:
            uploaded_file = client.files.upload(
                file=prepared_input.media_path,
                config={
                    "mime_type": prepared_input.mime_type,
                    "display_name": Path(
                        prepared_input.media_path
                    ).name,
                },
            )
        except TypeError:
            uploaded_file = client.files.upload(
                file=prepared_input.media_path
            )

        uploaded_file = wait_for_uploaded_file(
            client,
            uploaded_file,
        )

        return [prompt, uploaded_file], uploaded_file

    try:
        media_bytes = Path(
            prepared_input.media_path
        ).read_bytes()
    except OSError as exc:
        raise AIInputPreparationError(
            "The evidence media file could not be read."
        ) from exc

    media_part = types.Part.from_bytes(
        data=media_bytes,
        mime_type=(
            prepared_input.mime_type
            or "application/octet-stream"
        ),
    )

    return [prompt, media_part], None


def record_provider_attempt(
    analysis: AIAnalysis,
    *,
    provider_name: str,
    actor: Any = None,
    prompt: str,
    prepared_input: PreparedEvidenceInput,
    retry_index: int,
    configured_retry_count: int,
) -> int:
    """
    Atomically count one real provider generation request.

    This uses a conditional UPDATE instead of select_for_update(). SQLite
    ignores select_for_update(), while a conditional UPDATE is serialized by
    the database and therefore prevents the attempt counter from being
    incremented past max_api_attempts.
    """

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                status=AIAnalysis.Status.PROCESSING,
                api_attempts__lt=models.F("max_api_attempts"),
            )
            .update(
                api_attempts=models.F("api_attempts") + 1,
                updated_date=timezone.now(),
            )
        )

        if updated_rows != 1:
            current = AIAnalysis.objects.get(pk=analysis.pk)

            if current.status != AIAnalysis.Status.PROCESSING:
                raise AIAnalysisStateError(
                    "Provider requests require an analysis in Processing state."
                )

            raise AIAnalysisStateError(
                "Maximum API attempts have been reached."
            )

        current = AIAnalysis.objects.get(pk=analysis.pk)
        attempt_number = current.api_attempts

        create_analysis_log(
            current,
            AIAnalysisLog.EventType.PROVIDER_REQUEST,
            (
                f"{get_provider_display_name(provider_name)} "
                "provider request submitted."
            ),
            actor=actor,
            metadata={
                "attempt": attempt_number,
                "maximum_attempts": current.max_api_attempts,
                "internal_retry_index": retry_index,
                "configured_internal_retries": configured_retry_count,
                "model_name": current.model_name,
                "provider": provider_name,
                "pipeline_version": get_ai_pipeline_version(),
                "prompt_library_revision": PROMPT_LIBRARY_REVISION,
                "cache_key": current.cache_key,
                "ai_enabled": is_ai_enabled(),
                "request_timeout_seconds": get_ai_timeout_seconds(),
                "prompt_characters": len(prompt),
                "input_source_kind": prepared_input.source_kind,
                "media_attached": prepared_input.has_media,
                "media_mime_type": prepared_input.mime_type,
                "media_size_bytes": prepared_input.media_size_bytes,
                "atomic_attempt_increment": True,
            },
        )

    # Keep the in-memory object synchronized for retry/failure logging.
    analysis.api_attempts = attempt_number
    return attempt_number

def call_gemini(
    *,
    analysis: AIAnalysis,
    prompt: str,
    prepared_input: PreparedEvidenceInput,
    actor: Any = None,
) -> tuple[Any, str, TokenUsage, str]:
    """
    Call Gemini with bounded, auditable retries.

    Attempt strategy:
    1. Prefer a shallow machine-readable response schema.
    2. If Gemini rejects that request with 400 INVALID_ARGUMENT, switch the
       remaining attempt(s) to JSON MIME compatibility mode plus a compact
       JSON contract in the prompt.
    3. Empty/malformed JSON may also retry while the configured and database
       budgets permit.

    Every real generate_content call is still counted in api_attempts.
    """

    client = create_gemini_client()
    _, types = import_google_genai()
    model_name = get_gemini_model_name()

    configured_retry_count = get_non_negative_int_setting(
        "AIDEX_AI_MAX_RETRIES",
        DEFAULT_MAX_RETRIES,
    )

    retry_base_seconds = get_positive_float_setting(
        "AIDEX_AI_RETRY_BASE_SECONDS",
        DEFAULT_RETRY_BASE_SECONDS,
    )

    remaining_attempt_budget = max(
        0,
        analysis.max_api_attempts - analysis.api_attempts,
    )

    if remaining_attempt_budget <= 0:
        raise AIAnalysisStateError(
            "Maximum API attempts have been reached."
        )

    provider_call_limit = min(
        configured_retry_count + 1,
        remaining_attempt_budget,
    )

    use_response_schema = True
    last_error: AIServiceError | None = None

    for retry_index in range(
        provider_call_limit
    ):
        uploaded_file = None
        response = None
        response_text = ""

        active_prompt = (
            prompt
            if use_response_schema
            else build_json_compatibility_prompt(
                prompt
            )
        )

        generation_config = _build_generation_config(
            types,
            use_response_schema=use_response_schema,
        )

        try:
            contents, uploaded_file = build_gemini_contents(
                client=client,
                types=types,
                prompt=active_prompt,
                prepared_input=prepared_input,
            )

            attempt_number = record_provider_attempt(
                analysis,
                provider_name="GEMINI",
                actor=actor,
                prompt=active_prompt,
                prepared_input=prepared_input,
                retry_index=retry_index,
                configured_retry_count=(
                    configured_retry_count
                ),
            )

            response = client.models.generate_content(
                model=model_name,
                contents=contents,
                config=generation_config,
            )

            parsed_preview = (
                get_response_parsed_object(
                    response
                )
            )

            response_text = get_response_text(
                response
            )

            if parsed_preview is None:
                if not response_text:
                    raise AIProviderResponseError(
                        "Gemini returned no usable structured result."
                    )

                try:
                    parsed_preview = extract_json_object(
                        response_text
                    )
                except AIProviderResponseError as exc:
                    finish_reason = get_response_finish_reason(
                        response
                    )

                    if finish_reason in {
                        "MAX_TOKENS",
                        "MAX_OUTPUT_TOKENS",
                        "LENGTH",
                    }:
                        raise AIProviderResponseError(
                            (
                                "Gemini returned incomplete JSON because "
                                "the response reached its output-token limit."
                            )
                        ) from exc

                    raise

            if not normalize_whitespace(
                parsed_preview.get(
                    "summary"
                )
            ):
                raise AIProviderResponseError(
                    "Gemini JSON did not include a summary."
                )

            if not response_text:
                response_text = json.dumps(
                    parsed_preview,
                    ensure_ascii=False,
                )

            logger.info(
                (
                    "Gemini request succeeded for %s on attempt %s/%s "
                    "(response_schema=%s)."
                ),
                analysis.analysis_number,
                attempt_number,
                analysis.max_api_attempts,
                use_response_schema,
            )

            return (
                response,
                response_text,
                extract_token_usage(
                    response
                ),
                get_provider_request_id(
                    response
                ),
            )

        except Exception as exc:
            raw_invalid_argument = (
                is_invalid_argument_error(
                    exc
                )
            )

            service_error = (
                exc
                if isinstance(
                    exc,
                    AIServiceError,
                )
                else classify_provider_exception(
                    exc,
                    provider_name="GEMINI",
                )
            )

            last_error = service_error

            has_retry_left = (
                retry_index + 1
                < provider_call_limit
            )

            has_database_budget_left = (
                analysis.api_attempts
                < analysis.max_api_attempts
            )

            # Most important compatibility path: do not repeat the exact same
            # rejected structured-schema request.
            if (
                raw_invalid_argument
                and use_response_schema
                and has_retry_left
                and has_database_budget_left
            ):
                use_response_schema = False

                create_analysis_log(
                    analysis,
                    AIAnalysisLog.EventType.PROVIDER_RESPONSE,
                    (
                        "Gemini rejected the structured response schema; "
                        "switching to JSON compatibility mode."
                    ),
                    actor=actor,
                    metadata={
                        "attempt": analysis.api_attempts,
                        "model_name": model_name,
                        "fallback": "json_mime_without_schema",
                        "error": truncate_text(
                            normalize_whitespace(
                                str(exc)
                            ),
                            MAX_LOG_METADATA_TEXT,
                        ),
                    },
                )

                logger.warning(
                    (
                        "Gemini rejected response schema for %s; "
                        "retrying in JSON compatibility mode."
                    ),
                    analysis.analysis_number,
                )

                # No exponential delay is needed for a deterministic request
                # shape rejection.
                continue

            retryable = isinstance(
                service_error,
                (
                    AIProviderUnavailableError,
                    AIProviderTimeoutError,
                    AIProviderResponseError,
                ),
            )

            if isinstance(
                service_error,
                AIProviderResponseError,
            ):
                logger.warning(
                    (
                        "Gemini response validation failed for %s. "
                        "Diagnostics: %s. Error: %s"
                    ),
                    analysis.analysis_number,
                    get_response_diagnostics(
                        response,
                        response_text,
                    ),
                    service_error,
                )

            if (
                not retryable
                or not has_retry_left
                or not has_database_budget_left
            ):
                raise service_error from exc

            sleep_seconds = (
                retry_base_seconds
                * (2 ** retry_index)
            )

            logger.warning(
                (
                    "Gemini request retry %s/%s for %s after %.2f seconds. "
                    "Provider attempts used: %s/%s. Error: %s"
                ),
                retry_index + 1,
                provider_call_limit - 1,
                analysis.analysis_number,
                sleep_seconds,
                analysis.api_attempts,
                analysis.max_api_attempts,
                service_error,
            )

            time.sleep(
                sleep_seconds
            )

        finally:
            if uploaded_file is not None:
                delete_uploaded_file_safely(
                    client,
                    uploaded_file,
                )

    raise (
        last_error
        or AIProviderUnavailableError(
            "Gemini provider request failed."
        )
    )


def import_openai_sdk():
    """Import the OpenAI-compatible client used for OpenRouter."""

    try:
        from openai import OpenAI
    except ImportError as exc:
        raise AIProviderUnavailableError(
            "OpenAI SDK is not installed. Run: pip install openai"
        ) from exc

    return OpenAI


def create_openrouter_client():
    """Create an OpenAI-compatible client pointed at OpenRouter."""

    ensure_ai_enabled()
    openai_client = import_openai_sdk()

    return openai_client(
        api_key=get_openrouter_api_key(),
        base_url=get_openrouter_base_url(),
        timeout=float(get_ai_timeout_seconds()),
    )


def get_openrouter_response_format(
    *,
    use_response_schema: bool,
) -> dict[str, Any]:
    """Build OpenRouter structured JSON or compatibility JSON mode."""

    if not use_response_schema:
        return {
            "type": "json_object",
        }

    schema = json.loads(
        json.dumps(get_analysis_response_json_schema())
    )
    schema["additionalProperties"] = False
    schema["required"] = list(
        schema.get("properties", {}).keys()
    )

    for nullable_score in (
        "confidence_score",
        "risk_score",
    ):
        score_schema = schema.get(
            "properties",
            {},
        ).get(nullable_score)

        if isinstance(score_schema, dict):
            score_schema["type"] = [
                "number",
                "null",
            ]

    return {
        "type": "json_schema",
        "json_schema": {
            "name": "aidex_forensic_analysis",
            "strict": True,
            "schema": schema,
        },
    }


def build_openrouter_messages(
    *,
    prompt: str,
    prepared_input: PreparedEvidenceInput,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Build OpenRouter text/image/PDF/audio/video chat content.

    Evidence bytes are read only from AIDEX's short-lived decrypted temporary
    path. The existing PreparedEvidenceInput cleanup removes that plaintext
    after the provider call finishes.
    """

    user_content: str | list[dict[str, Any]] = prompt
    extra_body: dict[str, Any] = {}

    if prepared_input.has_media:
        maximum_media_bytes = get_positive_int_setting(
            "AIDEX_OPENROUTER_MAX_MEDIA_BYTES",
            DEFAULT_MAX_UPLOAD_MEDIA_BYTES,
        )

        if prepared_input.media_size_bytes > maximum_media_bytes:
            raise AIInputPreparationError(
                "Evidence file exceeds the configured OpenRouter media limit."
            )

        try:
            media_bytes = Path(
                prepared_input.media_path
            ).read_bytes()
        except OSError as exc:
            raise AIInputPreparationError(
                "The evidence media file could not be read."
            ) from exc

        encoded_media = base64.b64encode(
            media_bytes
        ).decode("ascii")
        mime_type = (
            prepared_input.mime_type
            or "application/octet-stream"
        )
        extension = (
            Path(prepared_input.media_path)
            .suffix
            .lower()
            .lstrip(".")
        )
        user_content = [
            {
                "type": "text",
                "text": prompt,
            },
        ]

        if mime_type.startswith("image/"):
            user_content.append({
                "type": "image_url",
                "image_url": {
                    "url": (
                        f"data:{mime_type};base64,{encoded_media}"
                    ),
                },
            })

        elif mime_type == "application/pdf" or extension == "pdf":
            user_content.append({
                "type": "file",
                "file": {
                    "filename": Path(
                        prepared_input.media_path
                    ).name,
                    "file_data": (
                        "data:application/pdf;base64,"
                        f"{encoded_media}"
                    ),
                },
            })
            extra_body["plugins"] = [{
                "id": "file-parser",
                "pdf": {
                    "engine": str(
                        get_setting(
                            "AIDEX_OPENROUTER_PDF_ENGINE",
                            "cloudflare-ai",
                        )
                        or "cloudflare-ai"
                    ).strip(),
                },
            }]

        elif mime_type.startswith("audio/"):
            user_content.append({
                "type": "input_audio",
                "input_audio": {
                    "data": encoded_media,
                    "format": extension or "wav",
                },
            })

        elif mime_type.startswith("video/"):
            user_content.append({
                "type": "video_url",
                "video_url": {
                    "url": (
                        f"data:{mime_type};base64,{encoded_media}"
                    ),
                },
            })

        else:
            raise AIInputPreparationError(
                "OpenRouter cannot safely send this evidence media type."
            )

    return (
        [
            {
                "role": "system",
                "content": get_system_instruction(),
            },
            {
                "role": "user",
                "content": user_content,
            },
        ],
        extra_body,
    )


def call_openrouter(
    *,
    analysis: AIAnalysis,
    prompt: str,
    prepared_input: PreparedEvidenceInput,
    actor: Any = None,
) -> tuple[Any, str, TokenUsage, str]:
    """Call OpenRouter with bounded, auditable structured-output retries."""

    client = create_openrouter_client()
    model_name = get_openrouter_model_name()
    configured_retry_count = get_non_negative_int_setting(
        "AIDEX_AI_MAX_RETRIES",
        DEFAULT_MAX_RETRIES,
    )
    retry_base_seconds = get_positive_float_setting(
        "AIDEX_AI_RETRY_BASE_SECONDS",
        DEFAULT_RETRY_BASE_SECONDS,
    )
    remaining_attempt_budget = max(
        0,
        analysis.max_api_attempts - analysis.api_attempts,
    )

    if remaining_attempt_budget <= 0:
        raise AIAnalysisStateError(
            "Maximum API attempts have been reached."
        )

    provider_call_limit = min(
        configured_retry_count + 1,
        remaining_attempt_budget,
    )
    use_response_schema = True
    last_error: AIServiceError | None = None

    for retry_index in range(provider_call_limit):
        response = None
        response_text = ""
        active_prompt = (
            prompt
            if use_response_schema
            else build_json_compatibility_prompt(prompt)
        )

        try:
            messages, extra_body = build_openrouter_messages(
                prompt=active_prompt,
                prepared_input=prepared_input,
            )
            attempt_number = record_provider_attempt(
                analysis,
                provider_name="OPENROUTER",
                actor=actor,
                prompt=active_prompt,
                prepared_input=prepared_input,
                retry_index=retry_index,
                configured_retry_count=configured_retry_count,
            )
            request_arguments: dict[str, Any] = {
                "model": model_name,
                "messages": messages,
                "temperature": float(
                    get_setting("AIDEX_AI_TEMPERATURE", 0.1)
                    or 0.1
                ),
                "max_tokens": get_openrouter_max_output_tokens(),
                "response_format": get_openrouter_response_format(
                    use_response_schema=use_response_schema,
                ),
            }
            attribution_headers = get_openrouter_attribution_headers()

            if attribution_headers:
                request_arguments["extra_headers"] = attribution_headers

            if extra_body:
                request_arguments["extra_body"] = extra_body

            response = client.chat.completions.create(
                **request_arguments
            )

            response_error = getattr(response, "error", None)

            if response_error:
                raise AIProviderUnavailableError(
                    redact_provider_secrets(response_error)
                )

            response_text = get_response_text(response)

            if not response_text:
                raise AIProviderResponseError(
                    "OpenRouter returned no usable structured result."
                )

            try:
                parsed_preview = extract_json_object(response_text)
            except AIProviderResponseError as exc:
                finish_reason = get_response_finish_reason(response)

                if finish_reason in {
                    "MAX_TOKENS",
                    "MAX_OUTPUT_TOKENS",
                    "LENGTH",
                }:
                    raise AIProviderResponseError(
                        "OpenRouter returned incomplete JSON because the "
                        "response reached its output-token limit."
                    ) from exc

                raise

            if not normalize_whitespace(parsed_preview.get("summary")):
                raise AIProviderResponseError(
                    "OpenRouter JSON did not include a summary."
                )

            logger.info(
                (
                    "OpenRouter request succeeded for %s on attempt %s/%s "
                    "(response_schema=%s)."
                ),
                analysis.analysis_number,
                attempt_number,
                analysis.max_api_attempts,
                use_response_schema,
            )

            return (
                response,
                response_text,
                extract_token_usage(response),
                get_provider_request_id(response),
            )

        except Exception as exc:
            raw_invalid_argument = is_invalid_argument_error(exc)
            service_error = (
                exc
                if isinstance(exc, AIServiceError)
                else classify_provider_exception(
                    exc,
                    provider_name="OPENROUTER",
                )
            )
            last_error = service_error
            has_retry_left = retry_index + 1 < provider_call_limit
            has_database_budget_left = (
                analysis.api_attempts < analysis.max_api_attempts
            )

            if (
                raw_invalid_argument
                and use_response_schema
                and has_retry_left
                and has_database_budget_left
            ):
                use_response_schema = False
                create_analysis_log(
                    analysis,
                    AIAnalysisLog.EventType.PROVIDER_RESPONSE,
                    "OpenRouter rejected the structured response schema; "
                    "switching to JSON compatibility mode.",
                    actor=actor,
                    metadata={
                        "attempt": analysis.api_attempts,
                        "model_name": model_name,
                        "fallback": "json_object_without_schema",
                        "error": truncate_text(
                            redact_provider_secrets(exc),
                            MAX_LOG_METADATA_TEXT,
                        ),
                    },
                )
                logger.warning(
                    "OpenRouter rejected response schema for %s; retrying "
                    "in JSON compatibility mode.",
                    analysis.analysis_number,
                )
                continue

            retryable = isinstance(
                service_error,
                (
                    AIProviderUnavailableError,
                    AIProviderTimeoutError,
                    AIProviderResponseError,
                ),
            )

            if (
                not retryable
                or not has_retry_left
                or not has_database_budget_left
            ):
                raise service_error from exc

            sleep_seconds = retry_base_seconds * (2 ** retry_index)
            logger.warning(
                (
                    "OpenRouter request retry %s/%s for %s after %.2f "
                    "seconds. Provider attempts used: %s/%s. Error: %s"
                ),
                retry_index + 1,
                provider_call_limit - 1,
                analysis.analysis_number,
                sleep_seconds,
                analysis.api_attempts,
                analysis.max_api_attempts,
                service_error,
            )
            time.sleep(sleep_seconds)

    raise (
        last_error
        or AIProviderUnavailableError(
            "OpenRouter provider request failed."
        )
    )


def call_local_ai(
    *,
    analysis: AIAnalysis,
    prompt: str,
    prepared_input: PreparedEvidenceInput,
    actor: Any = None,
) -> tuple[Any, str, TokenUsage, str]:
    """
    Produce an offline forensic-style analysis for free demo deployments.

    This keeps the AIDEX AI workflow runnable when no external provider key is
    configured. The result is deterministic and audit logged as a local model,
    so it should be treated as demo assistance rather than a remote LLM result.
    """

    attempt_number = record_provider_attempt(
        analysis,
        provider_name="LOCAL",
        actor=actor,
        prompt=prompt,
        prepared_input=prepared_input,
        retry_index=0,
        configured_retry_count=0,
    )

    evidence_text = normalize_whitespace(
        prepared_input.text
    )
    lowered_text = evidence_text.casefold()
    suspicious_terms = [
        "password", "otp", "urgent", "verify", "bank",
        "crypto", "wallet", "transfer", "login", "click",
        "malware", "phishing", "credential", "upi", "account",
    ]
    matched_terms = [
        term
        for term in suspicious_terms
        if term in lowered_text
    ]
    risk_score = min(
        95,
        35 + (len(matched_terms) * 10),
    ) if matched_terms else 15
    threat_level = infer_threat_level(
        "",
        Decimal(str(risk_score)),
    )

    parsed = {
        "summary": (
            "Local AI demo analysis found suspicious indicators in the "
            "submitted evidence."
            if matched_terms
            else (
                "Local AI demo analysis completed and found no strong "
                "suspicious indicators in the submitted evidence."
            )
        ),
        "confidence_score": 86 if matched_terms else 62,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "extracted_text": truncate_text(
            evidence_text,
            4000,
        ),
        "keywords": matched_terms[:30],
        "entities": [],
        "findings": [
            {
                "title": "Suspicious language detected",
                "severity": threat_level,
                "details": (
                    "The evidence contains terms commonly associated with "
                    "credential theft, payment fraud, or phishing activity: "
                    f"{', '.join(matched_terms)}."
                ),
            }
        ] if matched_terms else [
            {
                "title": "No high-risk keyword cluster detected",
                "severity": "LOW",
                "details": (
                    "The local analyzer did not find the configured suspicious "
                    "keyword cluster in this evidence."
                ),
            }
        ],
        "recommendations": (
            "Preserve the original file hash, identify sender or account "
            "metadata, correlate any wallet or payment identifiers, and review "
            "the message source before taking enforcement action."
        ),
    }
    response_text = json.dumps(
        parsed,
        ensure_ascii=False,
    )

    response_object = {
        "provider": "LOCAL",
        "model_name": get_configured_model_name("LOCAL"),
        "parsed": parsed,
        "attempt": attempt_number,
    }

    return (
        response_object,
        response_text,
        TokenUsage(
            input_tokens=max(1, len(prompt) // 4),
            output_tokens=max(1, len(response_text) // 4),
        ),
        f"local-{analysis.pk}-{attempt_number}",
    )


def call_configured_provider(
    *,
    analysis: AIAnalysis,
    prompt: str,
    prepared_input: PreparedEvidenceInput,
    actor: Any = None,
) -> tuple[Any, str, TokenUsage, str]:
    """Dispatch one analysis to the configured provider adapter."""

    provider_name = get_analysis_provider_name(analysis)

    if provider_name == "LOCAL":
        return call_local_ai(
            analysis=analysis,
            prompt=prompt,
            prepared_input=prepared_input,
            actor=actor,
        )

    if provider_name == "OPENROUTER":
        return call_openrouter(
            analysis=analysis,
            prompt=prompt,
            prepared_input=prepared_input,
            actor=actor,
        )

    return call_gemini(
        analysis=analysis,
        prompt=prompt,
        prepared_input=prepared_input,
        actor=actor,
    )


# ============================================================================
# Response Normalization
# ============================================================================

def infer_threat_level(
    explicit_value: Any,
    risk_score: Decimal | None,
) -> str:
    normalized_value = (
        str(explicit_value or "")
        .strip()
        .upper()
        .replace(" ", "_")
    )

    valid_values = {
        value
        for value, _ in AIAnalysis.ThreatLevel.choices
    }

    if normalized_value in valid_values:
        return normalized_value

    if risk_score is None:
        return AIAnalysis.ThreatLevel.UNKNOWN
    if risk_score >= Decimal("80"):
        return AIAnalysis.ThreatLevel.CRITICAL
    if risk_score >= Decimal("60"):
        return AIAnalysis.ThreatLevel.HIGH
    if risk_score >= Decimal("30"):
        return AIAnalysis.ThreatLevel.MEDIUM
    if risk_score > Decimal("0"):
        return AIAnalysis.ThreatLevel.LOW

    return AIAnalysis.ThreatLevel.NONE


def normalize_provider_result(
    *,
    response_text: str,
    response_object: Any,
    token_usage: TokenUsage,
) -> NormalizedAnalysisResult:
    parsed = get_response_parsed_object(
        response_object
    )

    if parsed is None:
        try:
            parsed = extract_json_object(
                response_text
            )
        except AIProviderResponseError as exc:
            finish_reason = get_response_finish_reason(
                response_object
            )

            if finish_reason in {
                "MAX_TOKENS",
                "MAX_OUTPUT_TOKENS",
                "LENGTH",
            }:
                raise AIProviderResponseError(
                    (
                        "The provider returned incomplete output because "
                        "the response reached its output-token limit."
                    )
                ) from exc

            raise

    summary = normalize_whitespace(
        parsed.get(
            "summary"
        )
    )

    if not summary:
        raise AIProviderResponseError(
            "Provider structured output did not include a summary."
        )

    risk_score = safe_decimal_percentage(
        parsed.get(
            "risk_score"
        )
    )

    return NormalizedAnalysisResult(
        summary=summary,
        confidence_score=safe_decimal_percentage(
            parsed.get(
                "confidence_score"
            )
        ),
        risk_score=risk_score,
        threat_level=infer_threat_level(
            parsed.get(
                "threat_level"
            ),
            risk_score,
        ),
        extracted_text=normalize_whitespace(
            parsed.get(
                "extracted_text"
            )
        ),
        keywords=normalize_string_list(
            parsed.get(
                "keywords"
            ),
            maximum_items=30,
        ),
        entities=normalize_mapping_list(
            parsed.get(
                "entities"
            ),
            maximum_items=30,
        ),
        findings=normalize_mapping_list(
            parsed.get(
                "findings"
            ),
            maximum_items=30,
        ),
        recommendations=normalize_whitespace(
            parsed.get(
                "recommendations"
            )
        ),
        raw_response={
            "parsed": make_json_safe(
                parsed
            ),
            "sdk_response": make_json_safe(
                response_object
            ),
            "diagnostics": get_response_diagnostics(
                response_object,
                response_text,
            ),
            "structured_output_source": (
                "sdk_parsed"
                if get_response_parsed_object(
                    response_object
                )
                is not None
                else "text_fallback"
            ),
        },
        token_usage=token_usage,
    )


# ============================================================================
# Cache and Integrity
# ============================================================================

def build_cache_key_from_values(
    *,
    evidence_hash: Any,
    analysis_type: Any,
    prompt_version: Any,
    request_prompt: Any,
    provider: Any = AIAnalysis.Provider.GEMINI,
    model_name: str | None = None,
    pipeline_version: str | None = None,
) -> str:
    """
    Build a stable SHA-256 cache identity.

    The cache identity deliberately includes:
    - evidence SHA-256
    - analysis type
    - prompt version
    - prompt-library revision
    - exact normalized request prompt
    - provider
    - configured provider model
    - AIDEX pipeline version

    Returning a 64-character digest keeps the value safely inside the
    AIAnalysis.cache_key max_length while avoiding stale reuse after model or
    pipeline upgrades.
    """

    canonical_identity = {
        "analysis_type": str(analysis_type or "").strip(),
        "evidence_hash": str(evidence_hash or "").strip().lower(),
        "model_name": str(
            model_name
            if model_name is not None
            else get_configured_model_name()
        ).strip(),
        "pipeline_version": str(
            pipeline_version
            if pipeline_version is not None
            else get_ai_pipeline_version()
        ).strip(),
        "prompt_library_revision": PROMPT_LIBRARY_REVISION,
        "prompt_version": str(prompt_version or "").strip(),
        "provider": str(provider or "").strip(),
        "request_prompt": normalize_whitespace(
            request_prompt
        ),
    }

    serialized_identity = json.dumps(
        canonical_identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        serialized_identity.encode("utf-8")
    ).hexdigest()


def build_cache_key(
    analysis: AIAnalysis,
) -> str:
    return build_cache_key_from_values(
        evidence_hash=(
            getattr(
                analysis.evidence,
                "sha256_hash",
                "",
            )
            or ""
        ),
        analysis_type=analysis.analysis_type,
        prompt_version=analysis.prompt_version,
        request_prompt=getattr(
            analysis,
            "request_prompt",
            "",
        ),
        provider=get_analysis_provider_name(analysis),
        model_name=get_configured_model_name(
            get_analysis_provider_name(analysis)
        ),
        pipeline_version=get_ai_pipeline_version(),
    )


def validate_evidence_integrity(
    analysis: AIAnalysis,
) -> None:
    evidence = analysis.evidence

    if not evidence.is_active:
        raise AIEvidenceIntegrityError(
            "Archived evidence cannot be analyzed."
        )

    current_hash = str(
        getattr(evidence, "sha256_hash", "") or ""
    ).strip()

    if not current_hash:
        raise AIEvidenceIntegrityError(
            "Evidence SHA-256 hash is unavailable."
        )

    stored_hash = str(
        getattr(analysis, "evidence_hash_at_analysis", "")
        or ""
    ).strip()

    if stored_hash and stored_hash != current_hash:
        raise AIEvidenceIntegrityError(
            "Evidence hash changed after the analysis request was created. "
            "Create a new analysis record."
        )


def find_reusable_analysis(
    analysis: AIAnalysis,
) -> AIAnalysis | None:
    expected_cache_key = build_cache_key(
        analysis
    )

    current_provider_name = get_analysis_provider_name(analysis)
    current_model_name = get_configured_model_name(
        current_provider_name
    )

    return (
        AIAnalysis.objects
        .filter(
            evidence=analysis.evidence,
            analysis_type=analysis.analysis_type,
            prompt_version=analysis.prompt_version,
            provider=current_provider_name,
            model_name=current_model_name,
            evidence_hash_at_analysis=(
                analysis.evidence.sha256_hash
            ),
            cache_key=expected_cache_key,
            status=AIAnalysis.Status.COMPLETED,
            is_active=True,
        )
        .exclude(pk=analysis.pk)
        .order_by("-completed_at", "-created_date")
        .first()
    )


def copy_cached_result(
    *,
    source: AIAnalysis,
    target: AIAnalysis,
    actor: Any = None,
) -> AIAnalysis:
    expected_cache_key = build_cache_key(
        target
    )

    if source.cache_key != expected_cache_key:
        raise AIAnalysisStateError(
            "The cached analysis is not compatible with the current "
            "model or AIDEX analysis pipeline."
        )

    target_provider_name = get_analysis_provider_name(target)

    if source.provider != target_provider_name:
        raise AIAnalysisStateError(
            "The cached analysis was produced by a different AI provider."
        )

    if source.model_name != get_configured_model_name(
        target_provider_name
    ):
        raise AIAnalysisStateError(
            "The cached analysis was produced by a different AI model."
        )

    with transaction.atomic():
        target.ai_summary = source.ai_summary
        target.extracted_text = source.extracted_text
        target.extracted_keywords = source.extracted_keywords
        target.detected_entities = source.detected_entities
        target.findings = source.findings
        target.recommendations = source.recommendations
        target.provider_response = source.provider_response
        target.provider = source.provider
        target.confidence_score = source.confidence_score
        target.risk_score = source.risk_score
        target.threat_level = source.threat_level
        target.model_name = source.model_name
        target.input_tokens = 0
        target.output_tokens = 0
        target.total_tokens = 0
        target.processing_time_seconds = Decimal("0.000")
        target.started_at = timezone.now()
        target.completed_at = timezone.now()
        target.status = AIAnalysis.Status.COMPLETED
        target.cached_result = True
        target.cache_status = AIAnalysis.CacheStatus.CACHED
        target.cache_key = expected_cache_key
        target.evidence_hash_at_analysis = (
            target.evidence.sha256_hash or ""
        )
        target.last_error = ""
        target.provider_error_code = ""
        target.quota_exceeded = False
        target.save()

        create_analysis_log(
            target,
            AIAnalysisLog.EventType.CACHE_HIT,
            "Matching completed AI analysis result reused.",
            actor=actor,
            metadata={
                "source_analysis_id": str(source.pk),
                "source_analysis_number": source.analysis_number,
                "cache_key": expected_cache_key,
                "model_name": source.model_name,
                "pipeline_version": get_ai_pipeline_version(),
                "prompt_library_revision": PROMPT_LIBRARY_REVISION,
            },
        )

    return target


# ============================================================================
# State Persistence
# ============================================================================

def mark_analysis_processing(
    analysis: AIAnalysis,
    *,
    actor: Any = None,
    prepared_input: PreparedEvidenceInput,
    prompt: str,
) -> AIAnalysis:
    if analysis.api_attempts >= analysis.max_api_attempts:
        raise AIAnalysisStateError(
            "Maximum API attempts have been reached."
        )

    analysis.status = AIAnalysis.Status.PROCESSING
    analysis.started_at = timezone.now()
    analysis.completed_at = None
    analysis.processing_time_seconds = None
    analysis.provider = get_analysis_provider_name(analysis)
    analysis.model_name = get_configured_model_name(
        analysis.provider
    )
    analysis.input_summary = truncate_text(
        prepared_input.text,
        get_positive_int_setting(
            "AIDEX_AI_STORED_INPUT_SUMMARY_CHARS",
            DEFAULT_STORED_INPUT_SUMMARY_CHARS,
        ),
    )
    # Keep request_prompt as the original user request/custom focus.
    # Do not overwrite it with the generated provider prompt. Doing so makes
    # later retries recursively embed an old full prompt inside a new one.
    analysis.evidence_hash_at_analysis = (
        analysis.evidence.sha256_hash or ""
    )
    analysis.cache_key = build_cache_key(analysis)
    analysis.cached_result = False
    analysis.cache_status = AIAnalysis.CacheStatus.NOT_CACHED
    analysis.last_error = ""
    analysis.provider_error_code = ""
    analysis.quota_exceeded = False
    analysis.save()

    create_analysis_log(
        analysis,
        AIAnalysisLog.EventType.STARTED,
        "AI analysis processing started.",
        actor=actor,
        metadata={
            "attempts_used_before_provider": analysis.api_attempts,
            "maximum_attempts": analysis.max_api_attempts,
            "provider": analysis.provider,
            "model_name": analysis.model_name,
            "pipeline_version": get_ai_pipeline_version(),
            "prompt_library_revision": PROMPT_LIBRARY_REVISION,
            "cache_key": analysis.cache_key,
            "generated_prompt_characters": len(prompt),
            "generated_prompt_sha256": hashlib.sha256(
                prompt.encode("utf-8")
            ).hexdigest(),
            "prepared_input": prepared_input.as_metadata(),
        },
    )

    return analysis


def save_completed_result(
    *,
    analysis: AIAnalysis,
    result: NormalizedAnalysisResult,
    started_monotonic: float,
    actor: Any = None,
    provider_request_id: str = "",
) -> AIAnalysis:
    """
    Persist a successful provider result only while the analysis still owns
    the active PROCESSING lifecycle state.

    The final write uses an atomic conditional UPDATE instead of saving the
    stale in-memory model instance. This prevents a concurrent archive/state
    change from being silently overwritten or from reactivating a record.
    """

    elapsed_seconds = max(
        0.0,
        time.monotonic() - started_monotonic,
    )

    provider_response = dict(
        result.raw_response
        or {}
    )

    provider_response["_aidex"] = {
        "pipeline_version": get_ai_pipeline_version(),
        "prompt_library_revision": PROMPT_LIBRARY_REVISION,
        "provider": analysis.provider,
        "model_name": (
            analysis.model_name
            or get_configured_model_name(
                get_analysis_provider_name(analysis)
            )
        ),
        "cache_key": analysis.cache_key,
        "evidence_hash": (
            analysis.evidence_hash_at_analysis
            or ""
        ),
    }

    completed_at = timezone.now()
    processing_time_seconds = Decimal(
        f"{elapsed_seconds:.3f}"
    )

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                is_active=True,
                status=AIAnalysis.Status.PROCESSING,
            )
            .update(
                ai_summary=result.summary,
                extracted_text=result.extracted_text,
                extracted_keywords=result.keywords,
                detected_entities=result.entities,
                findings=result.findings,
                recommendations=result.recommendations,
                provider_response=provider_response,
                confidence_score=result.confidence_score,
                risk_score=result.risk_score,
                threat_level=result.threat_level,
                input_tokens=result.token_usage.input_tokens,
                output_tokens=result.token_usage.output_tokens,
                total_tokens=result.token_usage.total_tokens,
                processing_time_seconds=processing_time_seconds,
                completed_at=completed_at,
                status=AIAnalysis.Status.COMPLETED,
                cached_result=False,
                cache_status=AIAnalysis.CacheStatus.NOT_CACHED,
                last_error="",
                provider_error_code="",
                quota_exceeded=False,
                updated_date=completed_at,
            )
        )

        if updated_rows != 1:
            current = AIAnalysis.objects.get(
                pk=analysis.pk
            )

            if not current.is_active:
                raise AIAnalysisStateError(
                    (
                        "The analysis was archived while provider execution "
                        "was in progress. The provider response was not "
                        "allowed to overwrite the archived record."
                    )
                )

            raise AIAnalysisStateError(
                (
                    "The analysis lifecycle changed before the provider "
                    "result could be saved."
                )
            )

        analysis.refresh_from_db()

        create_analysis_log(
            analysis,
            AIAnalysisLog.EventType.PROVIDER_RESPONSE,
            (
                f"{get_provider_display_name(analysis.provider)} provider "
                "response received and parsed."
            ),
            actor=actor,
            provider_request_id=provider_request_id,
            metadata={
                "input_tokens": result.token_usage.input_tokens,
                "output_tokens": result.token_usage.output_tokens,
                "total_tokens": result.token_usage.total_tokens,
                "model_name": analysis.model_name,
                "pipeline_version": get_ai_pipeline_version(),
                "cache_key": analysis.cache_key,
                "state_guard": "active_processing_compare_and_set",
            },
        )

        create_analysis_log(
            analysis,
            AIAnalysisLog.EventType.COMPLETED,
            "AI analysis completed successfully.",
            actor=actor,
            metadata={
                "processing_time_seconds": str(
                    analysis.processing_time_seconds
                ),
                "confidence_score": (
                    str(analysis.confidence_score)
                    if analysis.confidence_score is not None
                    else None
                ),
                "risk_score": (
                    str(analysis.risk_score)
                    if analysis.risk_score is not None
                    else None
                ),
                "threat_level": analysis.threat_level,
                "model_name": analysis.model_name,
                "pipeline_version": get_ai_pipeline_version(),
                "cache_key": analysis.cache_key,
                "state_guard": "active_processing_compare_and_set",
            },
        )

    return analysis


def save_failed_result(
    *,
    analysis: AIAnalysis,
    error: Exception,
    started_monotonic: float,
    actor: Any = None,
) -> AIAnalysis:
    """
    Persist a failed execution only if this analysis is still active and in
    PROCESSING state.

    If another lifecycle action has already changed or archived the record,
    failure handling must not overwrite that newer state.
    """

    elapsed_seconds = max(
        0.0,
        time.monotonic() - started_monotonic,
    )

    error_message = truncate_text(
        redact_provider_secrets(error)
        or error.__class__.__name__,
        MAX_ERROR_LENGTH,
    )

    error_code = error.__class__.__name__
    quota_exceeded = isinstance(
        error,
        AIProviderQuotaError,
    )
    failed_at = timezone.now()
    processing_time_seconds = Decimal(
        f"{elapsed_seconds:.3f}"
    )

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                is_active=True,
                status=AIAnalysis.Status.PROCESSING,
            )
            .update(
                status=AIAnalysis.Status.FAILED,
                completed_at=failed_at,
                processing_time_seconds=processing_time_seconds,
                last_error=error_message,
                provider_error_code=truncate_text(
                    error_code,
                    80,
                ),
                quota_exceeded=quota_exceeded,
                cached_result=False,
                cache_status=AIAnalysis.CacheStatus.NOT_CACHED,
                updated_date=failed_at,
            )
        )

        if updated_rows != 1:
            current = AIAnalysis.objects.get(
                pk=analysis.pk
            )

            logger.warning(
                (
                    "Skipped FAILED transition for analysis %s because "
                    "the lifecycle changed to status=%s, is_active=%s."
                ),
                current.analysis_number,
                current.status,
                current.is_active,
            )

            return current

        analysis.refresh_from_db()

        create_analysis_log(
            analysis,
            AIAnalysisLog.EventType.FAILED,
            "AI analysis failed.",
            actor=actor,
            metadata={
                "error_type": error_code,
                "error": truncate_text(
                    error_message,
                    MAX_LOG_METADATA_TEXT,
                ),
                "quota_exceeded": quota_exceeded,
                "attempt": analysis.api_attempts,
                "state_guard": "active_processing_compare_and_set",
            },
        )

    return analysis


# ============================================================================
# Main Orchestration
# ============================================================================

def validate_execution_state(
    analysis: AIAnalysis,
) -> None:
    """
    Validate whether an analysis can be claimed for execution.
    """

    if not analysis.is_active:
        raise AIAnalysisStateError(
            "Archived analysis records cannot be executed."
        )

    if analysis.status not in {
        AIAnalysis.Status.PENDING,
        AIAnalysis.Status.QUEUED,
        AIAnalysis.Status.FAILED,
    }:
        raise AIAnalysisStateError(
            (
                "Analysis must be pending, queued or retryable failed "
                "before execution."
            )
        )

    if analysis.quota_exceeded:
        raise AIAnalysisStateError(
            "Quota-exceeded analysis requires a later explicit retry."
        )

    if analysis.api_attempts >= analysis.max_api_attempts:
        raise AIAnalysisStateError(
            "Maximum API attempts have been reached."
        )


def claim_analysis_for_execution(
    analysis_id: Any,
) -> AIAnalysis:
    """
    Atomically claim one analysis for execution.

    The claim is a compare-and-set UPDATE:
        PENDING / QUEUED / FAILED -> PROCESSING

    Unlike select_for_update(), this works on SQLite because the write itself
    is serialized by SQLite. On databases with row-level locking it is also a
    single atomic state transition. Only one concurrent caller can update the
    row while it is in an executable state.
    """

    claim_started_at = timezone.now()

    with transaction.atomic():
        claimed_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis_id,
                is_active=True,
                status__in={
                    AIAnalysis.Status.PENDING,
                    AIAnalysis.Status.QUEUED,
                    AIAnalysis.Status.FAILED,
                },
                quota_exceeded=False,
                api_attempts__lt=models.F("max_api_attempts"),
            )
            .update(
                status=AIAnalysis.Status.PROCESSING,
                started_at=claim_started_at,
                completed_at=None,
                processing_time_seconds=None,
                cached_result=False,
                cache_status=AIAnalysis.CacheStatus.NOT_CACHED,
                last_error="",
                provider_error_code="",
                updated_date=claim_started_at,
            )
        )

        if claimed_rows != 1:
            try:
                current = (
                    AIAnalysis.objects
                    .select_related(
                        "evidence",
                        "evidence__case",
                        "created_by",
                    )
                    .get(pk=analysis_id)
                )
            except AIAnalysis.DoesNotExist as exc:
                raise AIAnalysisStateError(
                    "The requested analysis no longer exists."
                ) from exc

            if current.status == AIAnalysis.Status.PROCESSING:
                raise AIAnalysisStateError(
                    "This analysis is already being processed by another request."
                )

            validate_execution_state(current)

            raise AIAnalysisStateError(
                "The analysis could not be claimed for execution."
            )

        return (
            AIAnalysis.objects
            .select_related(
                "evidence",
                "evidence__case",
                "created_by",
            )
            .get(pk=analysis_id)
        )


def execute_analysis(
    analysis: AIAnalysis,
    *,
    actor: Any = None,
    allow_cache: bool = True,
    force: bool = False,
) -> ExecutionOutcome:
    """
    Claim and execute one analysis safely.

    Execution ownership is established with an atomic conditional UPDATE
    rather than relying only on select_for_update(). This prevents the same
    analysis from reaching an AI provider twice when concurrent requests are handled
    with SQLite as well as databases that support row-level locking.
    """

    started_monotonic = time.monotonic()
    execution_claimed = False
    provider_called = False
    prepared_input: PreparedEvidenceInput | None = None

    analysis_id = analysis.pk

    try:
        analysis = claim_analysis_for_execution(
            analysis_id
        )
        execution_claimed = True

        validate_evidence_integrity(
            analysis
        )

        if allow_cache and not force:
            reusable = find_reusable_analysis(
                analysis
            )

            if reusable is not None:
                copy_cached_result(
                    source=reusable,
                    target=analysis,
                    actor=actor,
                )

                return ExecutionOutcome(
                    analysis=analysis,
                    completed=True,
                    cached=True,
                    provider_called=False,
                )

        # Cache reuse above does not contact a provider. Any fresh analysis beyond
        # this point requires the master AI switch to be enabled.
        ensure_ai_enabled()

        prepared_input = prepare_evidence_input(
            analysis
        )

        prompt = build_analysis_prompt(
            analysis,
            prepared_input,
        )

        # The atomic claim already moved the row to PROCESSING. This function
        # now persists the model/input/cache metadata and STARTED audit event.
        mark_analysis_processing(
            analysis,
            actor=actor,
            prepared_input=prepared_input,
            prompt=prompt,
        )

        (
            response_object,
            response_text,
            token_usage,
            provider_request_id,
        ) = call_configured_provider(
            analysis=analysis,
            prompt=prompt,
            prepared_input=prepared_input,
            actor=actor,
        )

        provider_called = True

        normalized_result = normalize_provider_result(
            response_text=response_text,
            response_object=response_object,
            token_usage=token_usage,
        )

        save_completed_result(
            analysis=analysis,
            result=normalized_result,
            started_monotonic=started_monotonic,
            actor=actor,
            provider_request_id=provider_request_id,
        )

        return ExecutionOutcome(
            analysis=analysis,
            completed=True,
            cached=False,
            provider_called=True,
        )

    except Exception as exc:
        service_error = (
            exc
            if isinstance(
                exc,
                AIServiceError,
            )
            else AIServiceError(
                redact_provider_secrets(exc)
                or exc.__class__.__name__
            )
        )

        try:
            analysis = (
                AIAnalysis.objects
                .select_related(
                    "evidence",
                    "evidence__case",
                )
                .get(
                    pk=analysis_id
                )
            )
        except AIAnalysis.DoesNotExist:
            logger.exception(
                "AIDEX analysis disappeared during execution: %s",
                analysis_id,
            )

            raise service_error from exc

        provider_called = bool(
            analysis.api_attempts > 0
        )

        # Only the caller that successfully claimed the analysis may persist
        # an execution failure. A concurrent loser must never turn the winner's
        # PROCESSING/COMPLETED record into FAILED.
        if execution_claimed:
            save_failed_result(
                analysis=analysis,
                error=service_error,
                started_monotonic=started_monotonic,
                actor=actor,
            )

        logger.exception(
            "AIDEX AI analysis failed: %s",
            analysis.analysis_number,
        )

        return ExecutionOutcome(
            analysis=analysis,
            completed=False,
            cached=False,
            provider_called=provider_called,
            error=str(
                service_error
            ),
        )

    finally:
        if prepared_input is not None:
            prepared_input.cleanup()

def execute_queued_analysis(
    analysis_id: Any,
    *,
    actor: Any = None,
) -> ExecutionOutcome:
    analysis = AIAnalysis.objects.get(pk=analysis_id)

    if analysis.status != AIAnalysis.Status.QUEUED:
        raise AIAnalysisStateError(
            "Only queued analyses may be consumed by the executor."
        )

    return execute_analysis(
        analysis,
        actor=actor,
    )


def process_queued_analyses(
    *,
    limit: int = 5,
    actor: Any = None,
) -> list[ExecutionOutcome]:
    safe_limit = max(1, min(int(limit), 100))

    priority_order = Case(
        When(
            priority=AIAnalysis.Priority.CRITICAL,
            then=Value(5),
        ),
        When(
            priority=AIAnalysis.Priority.HIGH,
            then=Value(4),
        ),
        When(
            priority=AIAnalysis.Priority.MEDIUM,
            then=Value(3),
        ),
        When(
            priority=AIAnalysis.Priority.LOW,
            then=Value(2),
        ),
        default=Value(0),
        output_field=IntegerField(),
    )

    analysis_ids = list(
        AIAnalysis.objects
        .filter(
            status=AIAnalysis.Status.QUEUED,
            is_active=True,
            evidence__is_active=True,
        )
        .annotate(
            priority_rank=priority_order,
        )
        .order_by(
            "-priority_rank",
            "created_date",
        )
        .values_list(
            "pk",
            flat=True,
        )[:safe_limit]
    )

    outcomes: list[ExecutionOutcome] = []

    for analysis_id in analysis_ids:
        try:
            outcomes.append(
                execute_queued_analysis(
                    analysis_id,
                    actor=actor,
                )
            )
        except AIServiceError as exc:
            analysis = AIAnalysis.objects.get(pk=analysis_id)

            outcomes.append(
                ExecutionOutcome(
                    analysis=analysis,
                    completed=False,
                    error=str(exc),
                )
            )

    return outcomes


# ============================================================================
# Maintenance
# ============================================================================

def invalidate_stale_results(
    *,
    limit: int = 500,
) -> int:
    """
    Invalidate completed cache entries that no longer match current evidence,
    configured model or AIDEX pipeline identity.
    """

    safe_limit = max(1, min(int(limit), 5_000))

    analyses = (
        AIAnalysis.objects
        .select_related("evidence")
        .filter(
            status=AIAnalysis.Status.COMPLETED,
            is_active=True,
            provider__in=SUPPORTED_AI_PROVIDERS,
        )[:safe_limit]
    )

    invalidated_count = 0
    current_pipeline_version = get_ai_pipeline_version()

    for analysis in analyses:
        current_model_name = get_configured_model_name(
            get_analysis_provider_name(analysis)
        )
        expected_cache_key = build_cache_key(
            analysis
        )

        evidence_changed = bool(
            analysis.result_is_stale
        )

        cache_identity_changed = bool(
            not analysis.cache_key
            or analysis.cache_key != expected_cache_key
            or analysis.model_name != current_model_name
        )

        if (
            not evidence_changed
            and not cache_identity_changed
        ):
            continue

        with transaction.atomic():
            analysis.cached_result = False
            analysis.cache_status = (
                AIAnalysis.CacheStatus.INVALIDATED
            )
            analysis.save(
                update_fields=[
                    "cached_result",
                    "cache_status",
                    "updated_date",
                ]
            )

            create_analysis_log(
                analysis,
                AIAnalysisLog.EventType.CACHE_INVALIDATED,
                (
                    "Cached result invalidated because its evidence, "
                    "model or AIDEX pipeline identity is stale."
                ),
                metadata={
                    "evidence_changed": evidence_changed,
                    "cache_identity_changed": (
                        cache_identity_changed
                    ),
                    "analysis_hash": (
                        analysis.evidence_hash_at_analysis
                    ),
                    "current_evidence_hash": (
                        analysis.evidence.sha256_hash
                    ),
                    "stored_cache_key": analysis.cache_key,
                    "expected_cache_key": expected_cache_key,
                    "stored_model_name": analysis.model_name,
                    "current_model_name": current_model_name,
                    "current_pipeline_version": (
                        current_pipeline_version
                    ),
                },
            )

        invalidated_count += 1

    return invalidated_count


def reset_failed_analysis(
    analysis: AIAnalysis,
    *,
    actor: Any = None,
) -> AIAnalysis:
    if analysis.status != AIAnalysis.Status.FAILED:
        raise AIAnalysisStateError(
            "Only failed analyses can be reset."
        )

    with transaction.atomic():
        previous_error = analysis.last_error
        previous_attempts = analysis.api_attempts
        analysis.status = AIAnalysis.Status.PENDING
        analysis.started_at = None
        analysis.completed_at = None
        analysis.processing_time_seconds = None
        analysis.api_attempts = 0
        analysis.last_error = ""
        analysis.provider_error_code = ""
        analysis.quota_exceeded = False
        analysis.cached_result = False
        analysis.cache_status = AIAnalysis.CacheStatus.NOT_CACHED
        analysis.save()

        create_analysis_log(
            analysis,
            AIAnalysisLog.EventType.RETRY,
            "Failed analysis reset for another explicit attempt.",
            actor=actor,
            metadata={
                "previous_error": truncate_text(
                    previous_error,
                    MAX_LOG_METADATA_TEXT,
                ),
                "previous_attempts": previous_attempts,
                "new_attempts_used": analysis.api_attempts,
                "maximum_attempts_per_cycle": analysis.max_api_attempts,
            },
        )

    return analysis


def cancel_analysis(
    analysis: AIAnalysis,
    *,
    actor: Any = None,
    reason: str = "",
) -> AIAnalysis:
    """
    Cancel Pending/Queued -> Cancelled with an atomic compare-and-set update.

    SQLite ignores select_for_update(), so the status observed by this caller
    must still be current at the exact write point. If Run/worker execution
    wins the race first, cancellation is rejected instead of overwriting the
    newer lifecycle state.
    """

    if not analysis.is_active:
        raise AIAnalysisStateError(
            "Archived analyses cannot be cancelled."
        )

    if analysis.status not in {
        AIAnalysis.Status.PENDING,
        AIAnalysis.Status.QUEUED,
    }:
        raise AIAnalysisStateError(
            "Only pending or queued analyses can be cancelled."
        )

    observed_status = analysis.status
    transition_time = timezone.now()

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                is_active=True,
                status=observed_status,
            )
            .update(
                status=AIAnalysis.Status.CANCELLED,
                completed_at=transition_time,
                last_error="",
                provider_error_code="",
                quota_exceeded=False,
                updated_date=transition_time,
            )
        )

        if updated_rows != 1:
            current = AIAnalysis.objects.get(
                pk=analysis.pk
            )

            raise AIAnalysisStateError(
                (
                    "The analysis lifecycle changed before cancellation "
                    f"completed (current status: {current.status})."
                )
            )

        analysis.refresh_from_db()

        create_analysis_log(
            analysis,
            AIAnalysisLog.EventType.CANCELLED,
            "AI analysis cancelled.",
            actor=actor,
            metadata={
                "reason": truncate_text(
                    normalize_whitespace(reason),
                    MAX_LOG_METADATA_TEXT,
                ),
                "previous_status": observed_status,
                "transition_strategy": "atomic_compare_and_set",
            },
        )

    return analysis

def archive_analysis(
    analysis: AIAnalysis,
    *,
    actor: Any = None,
    reason: str = "",
) -> AIAnalysis:
    """
    Archive an analysis only when no execution is queued or in progress.

    The transition is performed with an atomic compare-and-set UPDATE so it
    remains safe on SQLite, where select_for_update() does not provide a
    row-level lock. If execution wins the race first, archiving is rejected.
    """

    if not analysis.is_active:
        return analysis

    blocked_statuses = {
        AIAnalysis.Status.QUEUED,
        AIAnalysis.Status.PROCESSING,
    }

    if analysis.status in blocked_statuses:
        raise AIAnalysisStateError(
            (
                "Queued or processing analyses cannot be archived. "
                "Wait for execution to finish or cancel the queued request."
            )
        )

    observed_status = analysis.status
    archived_at = timezone.now()

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                is_active=True,
                status=observed_status,
            )
            .exclude(
                status__in=blocked_statuses
            )
            .update(
                is_active=False,
                updated_date=archived_at,
            )
        )

        if updated_rows != 1:
            current = AIAnalysis.objects.get(
                pk=analysis.pk
            )

            if not current.is_active:
                return current

            if current.status in blocked_statuses:
                raise AIAnalysisStateError(
                    (
                        "The analysis started or queued for execution before "
                        "the archive operation completed, so archiving was "
                        "blocked."
                    )
                )

            raise AIAnalysisStateError(
                (
                    "The analysis lifecycle changed while it was being "
                    "archived. Refresh and try again."
                )
            )

        analysis.refresh_from_db()

        create_analysis_log(
            analysis,
            AIAnalysisLog.EventType.ARCHIVED,
            "AI analysis archived.",
            actor=actor,
            metadata={
                "reason": truncate_text(
                    normalize_whitespace(reason),
                    MAX_LOG_METADATA_TEXT,
                ),
                "previous_status": observed_status,
                "transition_strategy": "atomic_compare_and_set",
            },
        )

    return analysis


def restore_analysis(
    analysis: AIAnalysis,
    *,
    actor: Any = None,
) -> AIAnalysis:
    """
    Restore an archived analysis with an atomic inactive->active transition.

    The linked evidence must still be active. Only the request that actually
    changes is_active writes the RESTORED audit event, preventing duplicate
    restore logs on SQLite.
    """

    if analysis.is_active:
        return analysis

    if not analysis.evidence.is_active:
        raise AIAnalysisStateError(
            "Restore the linked evidence before restoring this analysis."
        )

    observed_status = analysis.status
    transition_time = timezone.now()

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                is_active=False,
                status=observed_status,
                evidence__is_active=True,
            )
            .update(
                is_active=True,
                updated_date=transition_time,
            )
        )

        if updated_rows != 1:
            current = (
                AIAnalysis.objects
                .select_related("evidence")
                .get(pk=analysis.pk)
            )

            if current.is_active:
                raise AIAnalysisStateError(
                    "This analysis was already restored by another request."
                )

            if not current.evidence.is_active:
                raise AIAnalysisStateError(
                    "Restore the linked evidence before restoring this analysis."
                )

            raise AIAnalysisStateError(
                (
                    "The analysis lifecycle changed while it was being "
                    "restored. Refresh and try again."
                )
            )

        analysis.refresh_from_db()

        create_analysis_log(
            analysis,
            AIAnalysisLog.EventType.RESTORED,
            "AI analysis restored.",
            actor=actor,
            metadata={
                "previous_status": observed_status,
                "transition_strategy": "atomic_compare_and_set",
            },
        )

    return analysis

# ============================================================================
# Usage Reporting
# ============================================================================

def get_usage_summary(queryset=None) -> dict[str, Any]:
    from django.db.models import Avg, Count, Sum

    if queryset is None:
        queryset = AIAnalysis.objects.all()

    aggregates = queryset.aggregate(
        total_analyses=Count("id"),
        completed_analyses=Count(
            "id",
            filter=models.Q(
                status=AIAnalysis.Status.COMPLETED
            ),
        ),
        failed_analyses=Count(
            "id",
            filter=models.Q(
                status=AIAnalysis.Status.FAILED
            ),
        ),
        total_input_tokens=Sum("input_tokens"),
        total_output_tokens=Sum("output_tokens"),
        total_tokens=Sum("total_tokens"),
        average_processing_seconds=Avg(
            "processing_time_seconds"
        ),
        average_confidence=Avg("confidence_score"),
        average_risk=Avg("risk_score"),
    )

    return {
        key: value if value is not None else 0
        for key, value in aggregates.items()
    }
