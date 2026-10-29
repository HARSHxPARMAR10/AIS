\
"""
AIDEX AI Engine Providers

Provider abstraction and Gemini implementation for AI-assisted forensic
analysis.

This module centralizes:

- Provider configuration
- Google Gen AI SDK client creation
- Structured JSON generation
- Retry and backoff behavior
- Timeout and quota error normalization
- Token-usage extraction
- Provider request identifiers
- Safe response serialization
- Future provider extensibility

The module does not read evidence files and does not update AIAnalysis models.
Those responsibilities belong to the service orchestration layer.

Installation
------------
    pip install google-genai

Expected settings
-----------------
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    AI_MODEL = os.getenv("AI_MODEL", "gemini-2.5-flash")

Optional settings
-----------------
    AIDEX_AI_MAX_RETRIES = 2
    AIDEX_AI_RETRY_BASE_SECONDS = 2
    AIDEX_AI_TIMEOUT_SECONDS = 60
    AIDEX_AI_MAX_OUTPUT_TOKENS = 2048
    AIDEX_AI_TEMPERATURE = 0.2
"""

from __future__ import annotations

import json
import logging
import random
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Mapping, Sequence

from django.conf import settings


logger = logging.getLogger(__name__)


# ==========================================================
# Defaults
# ==========================================================

DEFAULT_PROVIDER = "GEMINI"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BASE_SECONDS = 2.0
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_MAX_OUTPUT_TOKENS = 2_048
DEFAULT_TEMPERATURE = 0.2
DEFAULT_TOP_P = 0.95
MAX_PROVIDER_ERROR_LENGTH = 8_000
MAX_PROVIDER_REQUEST_ID_LENGTH = 150


# ==========================================================
# Exceptions
# ==========================================================

class ProviderError(Exception):
    """Base exception for AI provider operations."""


class ProviderConfigurationError(ProviderError):
    """Raised when provider configuration is missing or invalid."""


class ProviderSDKUnavailableError(ProviderError):
    """Raised when the required provider SDK is not installed."""


class ProviderAuthenticationError(ProviderError):
    """Raised when authentication fails."""


class ProviderPermissionError(ProviderError):
    """Raised when the provider rejects access to a model or resource."""


class ProviderQuotaError(ProviderError):
    """Raised when provider quota or rate limits are exceeded."""


class ProviderTimeoutError(ProviderError):
    """Raised when a provider operation times out."""


class ProviderUnavailableError(ProviderError):
    """Raised when the provider service is temporarily unavailable."""


class ProviderRequestError(ProviderError):
    """Raised when a provider request is malformed or rejected."""


class ProviderResponseError(ProviderError):
    """Raised when provider output is empty or malformed."""


class ProviderSafetyError(ProviderError):
    """Raised when output is blocked by provider safety controls."""


# ==========================================================
# Enums and Data Objects
# ==========================================================

class ProviderName(str, Enum):
    GEMINI = "GEMINI"
    LOCAL = "LOCAL"
    MANUAL = "MANUAL"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class ProviderConfiguration:
    """
    Normalized configuration for one provider request.
    """

    provider: str
    model_name: str
    api_key: str = ""
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_base_seconds: float = DEFAULT_RETRY_BASE_SECONDS
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    top_p: float = DEFAULT_TOP_P
    response_mime_type: str = "application/json"

    def as_safe_dict(self) -> dict[str, Any]:
        """
        Return configuration without exposing the API key.
        """

        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "api_key_configured": bool(self.api_key),
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "retry_base_seconds": self.retry_base_seconds,
            "max_output_tokens": self.max_output_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "response_mime_type": self.response_mime_type,
        }


@dataclass(frozen=True, slots=True)
class ProviderTokenUsage:
    """
    Normalized provider token accounting.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    reasoning_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return max(
            0,
            self.input_tokens
            + self.output_tokens
            + self.reasoning_tokens,
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    """
    Provider-neutral generation request.
    """

    prompt: str
    system_instruction: str = ""
    response_schema: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def validate(self) -> None:
        """
        Validate required request values.
        """

        if not str(
            self.prompt or ""
        ).strip():
            raise ProviderRequestError(
                "Provider prompt cannot be empty."
            )


@dataclass(slots=True)
class ProviderResponse:
    """
    Provider-neutral normalized response.
    """

    provider: str
    model_name: str
    text: str
    parsed_json: dict[str, Any]
    token_usage: ProviderTokenUsage
    request_id: str = ""
    finish_reason: str = ""
    safety_ratings: list[dict[str, Any]] = field(
        default_factory=list
    )
    raw_response: dict[str, Any] = field(
        default_factory=dict
    )
    attempts: int = 1
    elapsed_seconds: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "text": self.text,
            "parsed_json": self.parsed_json,
            "token_usage": self.token_usage.as_dict(),
            "request_id": self.request_id,
            "finish_reason": self.finish_reason,
            "safety_ratings": self.safety_ratings,
            "raw_response": self.raw_response,
            "attempts": self.attempts,
            "elapsed_seconds": self.elapsed_seconds,
        }


# ==========================================================
# Settings Helpers
# ==========================================================

def get_setting(
    name: str,
    default: Any = None,
) -> Any:
    """
    Return a Django setting value.
    """

    return getattr(
        settings,
        name,
        default,
    )


def get_string_setting(
    name: str,
    default: str = "",
) -> str:
    """
    Return a normalized string setting.
    """

    return str(
        get_setting(
            name,
            default,
        )
        or default
    ).strip()


def get_int_setting(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """
    Read and clamp an integer setting.
    """

    raw_value = get_setting(
        name,
        default,
    )

    try:
        value = int(
            raw_value
        )
    except (
        TypeError,
        ValueError,
    ):
        value = default

    if minimum is not None:
        value = max(
            minimum,
            value,
        )

    if maximum is not None:
        value = min(
            maximum,
            value,
        )

    return value


def get_float_setting(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """
    Read and clamp a floating-point setting.
    """

    raw_value = get_setting(
        name,
        default,
    )

    try:
        value = float(
            raw_value
        )
    except (
        TypeError,
        ValueError,
    ):
        value = default

    if minimum is not None:
        value = max(
            minimum,
            value,
        )

    if maximum is not None:
        value = min(
            maximum,
            value,
        )

    return value


def get_provider_configuration(
    provider_name: str | None = None,
) -> ProviderConfiguration:
    """
    Build normalized provider configuration from Django settings.
    """

    normalized_provider = str(
        provider_name
        or get_string_setting(
            "AI_PROVIDER",
            DEFAULT_PROVIDER,
        )
    ).strip().upper()

    if normalized_provider != ProviderName.GEMINI.value:
        raise ProviderConfigurationError(
            (
                f"Unsupported AI provider '{normalized_provider}'. "
                "Only GEMINI is currently configured."
            )
        )

    api_key = get_string_setting(
        "GEMINI_API_KEY",
        "",
    )

    model_name = get_string_setting(
        "AI_MODEL",
        DEFAULT_GEMINI_MODEL,
    )

    if not api_key:
        raise ProviderConfigurationError(
            "GEMINI_API_KEY is not configured."
        )

    if not model_name:
        raise ProviderConfigurationError(
            "AI_MODEL is not configured."
        )

    return ProviderConfiguration(
        provider=normalized_provider,
        model_name=model_name,
        api_key=api_key,
        timeout_seconds=get_int_setting(
            "AIDEX_AI_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
            minimum=1,
            maximum=600,
        ),
        max_retries=get_int_setting(
            "AIDEX_AI_MAX_RETRIES",
            DEFAULT_MAX_RETRIES,
            minimum=0,
            maximum=10,
        ),
        retry_base_seconds=get_float_setting(
            "AIDEX_AI_RETRY_BASE_SECONDS",
            DEFAULT_RETRY_BASE_SECONDS,
            minimum=0.1,
            maximum=60.0,
        ),
        max_output_tokens=get_int_setting(
            "AIDEX_AI_MAX_OUTPUT_TOKENS",
            DEFAULT_MAX_OUTPUT_TOKENS,
            minimum=128,
            maximum=65_536,
        ),
        temperature=get_float_setting(
            "AIDEX_AI_TEMPERATURE",
            DEFAULT_TEMPERATURE,
            minimum=0.0,
            maximum=2.0,
        ),
        top_p=get_float_setting(
            "AIDEX_AI_TOP_P",
            DEFAULT_TOP_P,
            minimum=0.0,
            maximum=1.0,
        ),
        response_mime_type=get_string_setting(
            "AIDEX_AI_RESPONSE_MIME_TYPE",
            "application/json",
        ),
    )


# ==========================================================
# General Utilities
# ==========================================================

def truncate_text(
    value: Any,
    maximum_length: int,
) -> str:
    """
    Convert a value to text and truncate it.
    """

    text = str(
        value or ""
    )

    if len(text) <= maximum_length:
        return text

    return text[
        :maximum_length
    ]


def normalize_whitespace(
    value: Any,
) -> str:
    """
    Normalize provider error and response text.
    """

    text = str(
        value or ""
    ).replace(
        "\r\n",
        "\n",
    ).replace(
        "\r",
        "\n",
    )

    lines: list[str] = []

    for raw_line in text.splitlines():
        line = re.sub(
            r"[ \t]+",
            " ",
            raw_line,
        ).strip()

        lines.append(
            line
        )

    return "\n".join(
        lines
    ).strip()


def make_json_safe(
    value: Any,
) -> Any:
    """
    Convert SDK objects into JSON-safe Python values.
    """

    if value is None or isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):
        return value

    if isinstance(
        value,
        Decimal,
    ):
        return float(
            value
        )

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): make_json_safe(
                item_value
            )
            for key, item_value in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            make_json_safe(
                item
            )
            for item in value
        ]

    model_dump = getattr(
        value,
        "model_dump",
        None,
    )

    if callable(
        model_dump
    ):
        try:
            return make_json_safe(
                model_dump()
            )
        except Exception:
            pass

    to_json_dict = getattr(
        value,
        "to_json_dict",
        None,
    )

    if callable(
        to_json_dict
    ):
        try:
            return make_json_safe(
                to_json_dict()
            )
        except Exception:
            pass

    if hasattr(
        value,
        "__dict__",
    ):
        try:
            return {
                key: make_json_safe(
                    item_value
                )
                for key, item_value in vars(
                    value
                ).items()
                if not key.startswith(
                    "_"
                )
            }
        except Exception:
            pass

    return truncate_text(
        repr(value),
        2_000,
    )


def extract_json_object(
    response_text: str,
) -> dict[str, Any]:
    """
    Parse one JSON object from plain or fenced provider output.
    """

    text = str(
        response_text or ""
    ).strip()

    if not text:
        raise ProviderResponseError(
            "The provider returned an empty response."
        )

    fenced_match = re.search(
        r"```(?:json)?\s*(\{.*\})\s*```",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    if fenced_match:
        text = fenced_match.group(
            1
        ).strip()

    try:
        parsed = json.loads(
            text
        )
    except json.JSONDecodeError:
        first_brace = text.find(
            "{"
        )
        last_brace = text.rfind(
            "}"
        )

        if (
            first_brace < 0
            or last_brace <= first_brace
        ):
            raise ProviderResponseError(
                "The provider response did not contain JSON."
            )

        candidate = text[
            first_brace:last_brace + 1
        ]

        try:
            parsed = json.loads(
                candidate
            )
        except json.JSONDecodeError as exc:
            raise ProviderResponseError(
                "The provider returned invalid JSON."
            ) from exc

    if not isinstance(
        parsed,
        dict,
    ):
        raise ProviderResponseError(
            "Provider JSON must be an object."
        )

    return parsed


def calculate_retry_delay(
    attempt_number: int,
    base_seconds: float,
) -> float:
    """
    Return exponential backoff with small random jitter.
    """

    exponential_delay = base_seconds * (
        2 ** max(
            0,
            attempt_number - 1,
        )
    )

    jitter = random.uniform(
        0,
        min(
            1.0,
            base_seconds,
        ),
    )

    return exponential_delay + jitter


# ==========================================================
# Base Provider
# ==========================================================

class BaseAIProvider(ABC):
    """
    Provider-neutral interface for AI generation.
    """

    provider_name = ProviderName.OTHER.value

    def __init__(
        self,
        configuration: ProviderConfiguration,
    ) -> None:
        self.configuration = configuration

    @abstractmethod
    def generate(
        self,
        request: ProviderRequest,
    ) -> ProviderResponse:
        """
        Generate one provider response.
        """

        raise NotImplementedError

    def health_check(
        self,
    ) -> dict[str, Any]:
        """
        Return provider configuration health without consuming model quota.
        """

        return {
            "provider": self.provider_name,
            "configured": True,
            "configuration": (
                self.configuration.as_safe_dict()
            ),
        }


# ==========================================================
# Gemini Provider
# ==========================================================

class GeminiProvider(BaseAIProvider):
    """
    Google Gemini provider using the official Google Gen AI SDK.
    """

    provider_name = ProviderName.GEMINI.value

    def __init__(
        self,
        configuration: ProviderConfiguration,
    ) -> None:
        super().__init__(
            configuration
        )

        self._client = None
        self._types_module = None

    def _import_sdk(self):
        """
        Import google-genai lazily.
        """

        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:
            raise ProviderSDKUnavailableError(
                (
                    "Google Gen AI SDK is not installed. "
                    "Install it with: pip install google-genai"
                )
            ) from exc

        return genai, types

    def _get_types_module(self):
        """
        Return the SDK types module.
        """

        if self._types_module is None:
            _, self._types_module = self._import_sdk()

        return self._types_module

    def _get_client(self):
        """
        Create and cache a Gemini API client.
        """

        if self._client is None:
            genai, _ = self._import_sdk()

            try:
                self._client = genai.Client(
                    api_key=self.configuration.api_key
                )
            except Exception as exc:
                raise self._normalize_exception(
                    exc
                ) from exc

        return self._client

    def _build_generation_config(
        self,
        request: ProviderRequest,
    ):
        """
        Build GenerateContentConfig using supported SDK fields.
        """

        types = self._get_types_module()

        configuration_values: dict[str, Any] = {
            "temperature": (
                self.configuration.temperature
            ),
            "top_p": self.configuration.top_p,
            "max_output_tokens": (
                self.configuration.max_output_tokens
            ),
            "response_mime_type": (
                self.configuration.response_mime_type
            ),
        }

        if request.system_instruction:
            configuration_values[
                "system_instruction"
            ] = request.system_instruction

        if request.response_schema:
            configuration_values[
                "response_schema"
            ] = make_json_safe(
                request.response_schema
            )

        http_options_class = getattr(
            types,
            "HttpOptions",
            None,
        )

        if http_options_class is not None:
            try:
                configuration_values[
                    "http_options"
                ] = http_options_class(
                    timeout=(
                        self.configuration.timeout_seconds
                        * 1_000
                    )
                )
            except Exception:
                logger.debug(
                    "Gemini HttpOptions timeout could not be configured.",
                    exc_info=True,
                )

        try:
            return types.GenerateContentConfig(
                **configuration_values
            )
        except Exception:
            configuration_values.pop(
                "response_schema",
                None,
            )

            configuration_values.pop(
                "http_options",
                None,
            )

            return types.GenerateContentConfig(
                **configuration_values
            )

    def _extract_response_text(
        self,
        response: Any,
    ) -> str:
        """
        Extract generated text from an SDK response.
        """

        direct_text = getattr(
            response,
            "text",
            None,
        )

        if direct_text:
            return str(
                direct_text
            ).strip()

        response_parts = getattr(
            response,
            "parts",
            None,
        ) or []

        collected_text: list[str] = []

        for part in response_parts:
            part_text = getattr(
                part,
                "text",
                None,
            )

            if part_text:
                collected_text.append(
                    str(part_text)
                )

        if collected_text:
            return "\n".join(
                collected_text
            ).strip()

        candidates = getattr(
            response,
            "candidates",
            None,
        ) or []

        for candidate in candidates:
            content = getattr(
                candidate,
                "content",
                None,
            )

            parts = getattr(
                content,
                "parts",
                None,
            ) or []

            for part in parts:
                part_text = getattr(
                    part,
                    "text",
                    None,
                )

                if part_text:
                    collected_text.append(
                        str(part_text)
                    )

        return "\n".join(
            collected_text
        ).strip()

    def _extract_token_usage(
        self,
        response: Any,
    ) -> ProviderTokenUsage:
        """
        Extract provider token metadata defensively.
        """

        usage_metadata = getattr(
            response,
            "usage_metadata",
            None,
        )

        if usage_metadata is None:
            return ProviderTokenUsage()

        input_tokens = (
            getattr(
                usage_metadata,
                "prompt_token_count",
                None,
            )
            or getattr(
                usage_metadata,
                "input_token_count",
                None,
            )
            or 0
        )

        output_tokens = (
            getattr(
                usage_metadata,
                "candidates_token_count",
                None,
            )
            or getattr(
                usage_metadata,
                "output_token_count",
                None,
            )
            or 0
        )

        cached_input_tokens = (
            getattr(
                usage_metadata,
                "cached_content_token_count",
                None,
            )
            or 0
        )

        reasoning_tokens = (
            getattr(
                usage_metadata,
                "thoughts_token_count",
                None,
            )
            or getattr(
                usage_metadata,
                "reasoning_token_count",
                None,
            )
            or 0
        )

        return ProviderTokenUsage(
            input_tokens=self._safe_token_integer(
                input_tokens
            ),
            output_tokens=self._safe_token_integer(
                output_tokens
            ),
            cached_input_tokens=self._safe_token_integer(
                cached_input_tokens
            ),
            reasoning_tokens=self._safe_token_integer(
                reasoning_tokens
            ),
        )

    @staticmethod
    def _safe_token_integer(
        value: Any,
    ) -> int:
        """
        Normalize a token count.
        """

        try:
            return max(
                0,
                int(value),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

    def _extract_request_id(
        self,
        response: Any,
    ) -> str:
        """
        Extract a provider response/request identifier when exposed.
        """

        for attribute_name in (
            "response_id",
            "request_id",
            "id",
        ):
            value = getattr(
                response,
                attribute_name,
                None,
            )

            if value:
                return truncate_text(
                    value,
                    MAX_PROVIDER_REQUEST_ID_LENGTH,
                )

        raw_response = make_json_safe(
            response
        )

        if isinstance(
            raw_response,
            dict,
        ):
            for key in (
                "response_id",
                "request_id",
                "id",
            ):
                value = raw_response.get(
                    key
                )

                if value:
                    return truncate_text(
                        value,
                        MAX_PROVIDER_REQUEST_ID_LENGTH,
                    )

        return ""

    def _extract_finish_reason(
        self,
        response: Any,
    ) -> str:
        """
        Return the first candidate finish reason.
        """

        candidates = getattr(
            response,
            "candidates",
            None,
        ) or []

        if not candidates:
            return ""

        finish_reason = getattr(
            candidates[0],
            "finish_reason",
            None,
        )

        if finish_reason is None:
            return ""

        name = getattr(
            finish_reason,
            "name",
            None,
        )

        return str(
            name or finish_reason
        )

    def _extract_safety_ratings(
        self,
        response: Any,
    ) -> list[dict[str, Any]]:
        """
        Normalize provider safety ratings.
        """

        candidates = getattr(
            response,
            "candidates",
            None,
        ) or []

        if not candidates:
            return []

        safety_ratings = getattr(
            candidates[0],
            "safety_ratings",
            None,
        ) or []

        normalized = make_json_safe(
            safety_ratings
        )

        return (
            normalized
            if isinstance(
                normalized,
                list,
            )
            else []
        )

    def _is_safety_blocked(
        self,
        response: Any,
    ) -> bool:
        """
        Return whether provider metadata indicates safety blocking.
        """

        prompt_feedback = getattr(
            response,
            "prompt_feedback",
            None,
        )

        block_reason = getattr(
            prompt_feedback,
            "block_reason",
            None,
        )

        if block_reason:
            block_reason_text = str(
                getattr(
                    block_reason,
                    "name",
                    block_reason,
                )
            ).upper()

            if block_reason_text not in {
                "",
                "BLOCK_REASON_UNSPECIFIED",
                "0",
                "NONE",
            }:
                return True

        finish_reason = self._extract_finish_reason(
            response
        ).upper()

        return finish_reason in {
            "SAFETY",
            "BLOCKED",
            "PROHIBITED_CONTENT",
        }

    def _normalize_exception(
        self,
        exc: Exception,
    ) -> ProviderError:
        """
        Convert SDK or transport exceptions into stable provider exceptions.
        """

        message = truncate_text(
            normalize_whitespace(
                str(exc)
            )
            or exc.__class__.__name__,
            MAX_PROVIDER_ERROR_LENGTH,
        )

        lowercase_message = message.casefold()
        class_name = exc.__class__.__name__.casefold()

        authentication_markers = (
            "api key not valid",
            "invalid api key",
            "unauthenticated",
            "authentication",
            "401",
        )

        permission_markers = (
            "permission denied",
            "permissiondenied",
            "forbidden",
            "403",
            "not permitted",
        )

        quota_markers = (
            "quota",
            "rate limit",
            "resource exhausted",
            "resourceexhausted",
            "too many requests",
            "429",
        )

        timeout_markers = (
            "timeout",
            "timed out",
            "deadline exceeded",
            "deadlineexceeded",
        )

        unavailable_markers = (
            "service unavailable",
            "temporarily unavailable",
            "unavailable",
            "503",
            "connection reset",
            "connection refused",
            "network",
        )

        request_markers = (
            "invalid argument",
            "invalidargument",
            "bad request",
            "400",
            "model not found",
            "404",
        )

        if any(
            marker in lowercase_message
            or marker in class_name
            for marker in authentication_markers
        ):
            return ProviderAuthenticationError(
                message
            )

        if any(
            marker in lowercase_message
            or marker in class_name
            for marker in permission_markers
        ):
            return ProviderPermissionError(
                message
            )

        if any(
            marker in lowercase_message
            or marker in class_name
            for marker in quota_markers
        ):
            return ProviderQuotaError(
                message
            )

        if any(
            marker in lowercase_message
            or marker in class_name
            for marker in timeout_markers
        ):
            return ProviderTimeoutError(
                message
            )

        if any(
            marker in lowercase_message
            or marker in class_name
            for marker in unavailable_markers
        ):
            return ProviderUnavailableError(
                message
            )

        if any(
            marker in lowercase_message
            or marker in class_name
            for marker in request_markers
        ):
            return ProviderRequestError(
                message
            )

        return ProviderUnavailableError(
            message
        )

    @staticmethod
    def _is_retryable_error(
        error: ProviderError,
    ) -> bool:
        """
        Return whether a normalized provider error may be retried.
        """

        return isinstance(
            error,
            (
                ProviderQuotaError,
                ProviderTimeoutError,
                ProviderUnavailableError,
            ),
        )

    def _generate_once(
        self,
        request: ProviderRequest,
    ) -> tuple[Any, str]:
        """
        Execute one Gemini request.
        """

        client = self._get_client()

        generation_config = self._build_generation_config(
            request
        )

        try:
            response = client.models.generate_content(
                model=self.configuration.model_name,
                contents=request.prompt,
                config=generation_config,
            )
        except Exception as exc:
            raise self._normalize_exception(
                exc
            ) from exc

        if self._is_safety_blocked(
            response
        ):
            raise ProviderSafetyError(
                "Gemini blocked the request or response for safety reasons."
            )

        response_text = self._extract_response_text(
            response
        )

        if not response_text:
            raise ProviderResponseError(
                "Gemini returned no textual content."
            )

        return response, response_text

    def generate(
        self,
        request: ProviderRequest,
    ) -> ProviderResponse:
        """
        Generate structured JSON with retry and normalized diagnostics.
        """

        request.validate()

        start_time = time.monotonic()

        total_attempts = (
            self.configuration.max_retries
            + 1
        )

        last_error: ProviderError | None = None

        for attempt_number in range(
            1,
            total_attempts + 1,
        ):
            try:
                response, response_text = self._generate_once(
                    request
                )

                parsed_json = extract_json_object(
                    response_text
                )

                elapsed_seconds = max(
                    0.0,
                    time.monotonic() - start_time,
                )

                return ProviderResponse(
                    provider=self.provider_name,
                    model_name=(
                        self.configuration.model_name
                    ),
                    text=response_text,
                    parsed_json=parsed_json,
                    token_usage=(
                        self._extract_token_usage(
                            response
                        )
                    ),
                    request_id=(
                        self._extract_request_id(
                            response
                        )
                    ),
                    finish_reason=(
                        self._extract_finish_reason(
                            response
                        )
                    ),
                    safety_ratings=(
                        self._extract_safety_ratings(
                            response
                        )
                    ),
                    raw_response=make_json_safe(
                        response
                    ),
                    attempts=attempt_number,
                    elapsed_seconds=elapsed_seconds,
                )

            except ProviderError as error:
                last_error = error

                is_last_attempt = (
                    attempt_number
                    >= total_attempts
                )

                if (
                    is_last_attempt
                    or not self._is_retryable_error(
                        error
                    )
                ):
                    raise

                retry_delay = calculate_retry_delay(
                    attempt_number,
                    self.configuration.retry_base_seconds,
                )

                logger.warning(
                    (
                        "Gemini request attempt %s/%s failed with %s. "
                        "Retrying in %.2f seconds."
                    ),
                    attempt_number,
                    total_attempts,
                    error.__class__.__name__,
                    retry_delay,
                )

                time.sleep(
                    retry_delay
                )

        raise last_error or ProviderUnavailableError(
            "Gemini request failed."
        )

    def health_check(
        self,
    ) -> dict[str, Any]:
        """
        Validate SDK and local configuration without making a model request.
        """

        sdk_available = True
        sdk_error = ""

        try:
            self._import_sdk()
        except ProviderSDKUnavailableError as exc:
            sdk_available = False
            sdk_error = str(
                exc
            )

        return {
            "provider": self.provider_name,
            "configured": bool(
                self.configuration.api_key
                and self.configuration.model_name
            ),
            "sdk_available": sdk_available,
            "sdk_error": sdk_error,
            "configuration": (
                self.configuration.as_safe_dict()
            ),
        }


# ==========================================================
# Provider Registry
# ==========================================================

PROVIDER_CLASS_REGISTRY: dict[str, type[BaseAIProvider]] = {
    ProviderName.GEMINI.value: GeminiProvider,
}


def register_provider(
    provider_name: str,
    provider_class: type[BaseAIProvider],
) -> None:
    """
    Register a provider class for future extensibility.
    """

    normalized_name = str(
        provider_name or ""
    ).strip().upper()

    if not normalized_name:
        raise ProviderConfigurationError(
            "Provider name cannot be empty."
        )

    if not issubclass(
        provider_class,
        BaseAIProvider,
    ):
        raise ProviderConfigurationError(
            "Provider class must inherit from BaseAIProvider."
        )

    PROVIDER_CLASS_REGISTRY[
        normalized_name
    ] = provider_class


def get_provider(
    provider_name: str | None = None,
    *,
    configuration: ProviderConfiguration | None = None,
) -> BaseAIProvider:
    """
    Build a configured provider instance.
    """

    normalized_configuration = (
        configuration
        or get_provider_configuration(
            provider_name
        )
    )

    normalized_name = str(
        normalized_configuration.provider
    ).strip().upper()

    provider_class = PROVIDER_CLASS_REGISTRY.get(
        normalized_name
    )

    if provider_class is None:
        raise ProviderConfigurationError(
            f"No provider class is registered for '{normalized_name}'."
        )

    return provider_class(
        normalized_configuration
    )


def generate_provider_response(
    *,
    prompt: str,
    system_instruction: str = "",
    response_schema: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    provider_name: str | None = None,
) -> ProviderResponse:
    """
    Convenience function for one provider request.
    """

    provider = get_provider(
        provider_name
    )

    request = ProviderRequest(
        prompt=prompt,
        system_instruction=system_instruction,
        response_schema=response_schema,
        metadata=metadata or {},
    )

    return provider.generate(
        request
    )


def get_provider_health(
    provider_name: str | None = None,
) -> dict[str, Any]:
    """
    Return local provider health information.
    """

    provider = get_provider(
        provider_name
    )

    return provider.health_check()


# ==========================================================
# Service Compatibility Adapter
# ==========================================================

def generate_forensic_json(
    *,
    prompt: str,
    system_instruction: str,
    response_schema: Mapping[str, Any] | None = None,
) -> tuple[
    dict[str, Any],
    ProviderResponse,
]:
    """
    Return parsed JSON and full provider response.

    This helper is convenient for services.py integrations.
    """

    provider_response = generate_provider_response(
        prompt=prompt,
        system_instruction=system_instruction,
        response_schema=response_schema,
    )

    return (
        provider_response.parsed_json,
        provider_response,
    )