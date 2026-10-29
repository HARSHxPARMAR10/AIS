\
"""
AIDEX OCR and Content Extraction Services

Professional, defensive and extensible extraction utilities for preparing
digital evidence before AI analysis.

Supported workflows
-------------------
- Plain text and log extraction
- CSV and JSON normalization
- PDF text extraction through pypdf when installed
- Image and screenshot OCR through pytesseract when installed
- Microsoft Office extraction hooks through python-docx/openpyxl/python-pptx
- Video frame extraction hooks through OpenCV when installed
- Audio transcription hooks for future local or provider integrations
- Large-file-safe bounded reading
- Structured extraction metadata
- Confidence and warning tracking
- Hash-aware extraction caching support
- No automatic external AI calls

Important design rule
---------------------
This module does not send evidence to Gemini or any other external provider.
It prepares a safe derived representation for the AI service layer.

Optional packages
-----------------
    pip install pypdf pillow pytesseract python-docx openpyxl python-pptx opencv-python

Tesseract itself must also be installed on the operating system when image
OCR is required.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import mimetypes
import os
import re
import tempfile
import zipfile
from abc import ABC, abstractmethod
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from django.conf import settings

from evidence.models import Evidence
from evidence.encrypted_storage import (
    materialize_decrypted_file,
    remove_temporary_plaintext,
)


logger = logging.getLogger(__name__)


_ACTIVE_DECRYPTED_PATHS: ContextVar[list[str] | None] = ContextVar(
    "aidex_ocr_decrypted_paths",
    default=None,
)


def cleanup_decrypted_evidence_paths(function):
    """Remove every plaintext path created during one extraction call."""

    @wraps(function)
    def wrapper(*args, **kwargs):
        temporary_paths: list[str] = []
        token = _ACTIVE_DECRYPTED_PATHS.set(
            temporary_paths
        )

        try:
            return function(*args, **kwargs)
        finally:
            for temporary_path in reversed(temporary_paths):
                remove_temporary_plaintext(
                    temporary_path
                )
            _ACTIVE_DECRYPTED_PATHS.reset(token)

    return wrapper


# ==========================================================
# Defaults and Limits
# ==========================================================

DEFAULT_MAX_TEXT_BYTES = 2_000_000
DEFAULT_MAX_OUTPUT_CHARACTERS = 100_000
DEFAULT_MAX_PDF_PAGES = 100
DEFAULT_MAX_IMAGE_PIXELS = 40_000_000
DEFAULT_MAX_VIDEO_FRAMES = 12
DEFAULT_VIDEO_FRAME_INTERVAL_SECONDS = 10
DEFAULT_MAX_ARCHIVE_MEMBERS = 200
DEFAULT_MAX_ARCHIVE_MEMBER_BYTES = 10_000_000
DEFAULT_MAX_TOTAL_ARCHIVE_BYTES = 50_000_000
DEFAULT_MAX_CSV_ROWS = 5_000
DEFAULT_MAX_SPREADSHEET_ROWS = 5_000
DEFAULT_MAX_PRESENTATION_SLIDES = 200

TEXT_EXTENSIONS = {
    "txt",
    "log",
    "md",
    "eml",
}

STRUCTURED_TEXT_EXTENSIONS = {
    "csv",
    "json",
    "xml",
}

IMAGE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "webp",
    "gif",
    "bmp",
    "tif",
    "tiff",
}

PDF_EXTENSIONS = {
    "pdf",
}

WORD_EXTENSIONS = {
    "docx",
}

SPREADSHEET_EXTENSIONS = {
    "xlsx",
}

PRESENTATION_EXTENSIONS = {
    "pptx",
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
}

BINARY_ONLY_EXTENSIONS = {
    "doc",
    "xls",
    "ppt",
    "rar",
    "7z",
}


# ==========================================================
# Exceptions
# ==========================================================

class OCRServiceError(Exception):
    """Base exception for content extraction operations."""


class OCRConfigurationError(OCRServiceError):
    """Raised when extraction configuration is invalid."""


class OCRDependencyError(OCRServiceError):
    """Raised when an optional extraction dependency is unavailable."""


class OCRUnsupportedFileError(OCRServiceError):
    """Raised when no extractor supports the selected file type."""


class OCRFileAccessError(OCRServiceError):
    """Raised when the evidence file cannot be accessed."""


class OCRFileTooLargeError(OCRServiceError):
    """Raised when safe configured processing limits are exceeded."""


class OCRCorruptedFileError(OCRServiceError):
    """Raised when a file cannot be parsed safely."""


class OCRExtractionError(OCRServiceError):
    """Raised when extraction fails unexpectedly."""


# ==========================================================
# Data Objects
# ==========================================================

@dataclass(slots=True)
class ExtractionWarning:
    """
    One non-fatal extraction warning.
    """

    code: str
    message: str
    details: dict[str, Any] = field(
        default_factory=dict
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


@dataclass(slots=True)
class ExtractionSegment:
    """
    One extracted content segment.

    Examples:
    - PDF page
    - OCR image
    - Spreadsheet worksheet
    - Presentation slide
    - Video frame
    """

    label: str
    text: str
    source_type: str
    sequence: int = 0
    confidence: float | None = None
    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "text": self.text,
            "source_type": self.source_type,
            "sequence": self.sequence,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class ExtractionResult:
    """
    Normalized extraction output for one evidence file.
    """

    text: str
    extractor_name: str
    source_extension: str
    mime_type: str = ""
    character_count: int = 0
    truncated: bool = False
    confidence: float | None = None
    segments: list[ExtractionSegment] = field(
        default_factory=list
    )
    warnings: list[ExtractionWarning] = field(
        default_factory=list
    )
    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @property
    def has_text(self) -> bool:
        return bool(
            self.text.strip()
        )

    @property
    def warning_count(self) -> int:
        return len(
            self.warnings
        )

    @property
    def segment_count(self) -> int:
        return len(
            self.segments
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "extractor_name": self.extractor_name,
            "source_extension": self.source_extension,
            "mime_type": self.mime_type,
            "character_count": self.character_count,
            "truncated": self.truncated,
            "confidence": self.confidence,
            "segments": [
                segment.as_dict()
                for segment in self.segments
            ],
            "warnings": [
                warning.as_dict()
                for warning in self.warnings
            ],
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class ExtractionContext:
    """
    Read-only extraction configuration.
    """

    maximum_output_characters: int
    maximum_text_bytes: int
    maximum_pdf_pages: int
    maximum_image_pixels: int
    maximum_video_frames: int
    video_frame_interval_seconds: int
    maximum_archive_members: int
    maximum_archive_member_bytes: int
    maximum_total_archive_bytes: int
    maximum_csv_rows: int
    maximum_spreadsheet_rows: int
    maximum_presentation_slides: int


# ==========================================================
# Settings Helpers
# ==========================================================

def get_setting(
    name: str,
    default: Any = None,
) -> Any:
    """
    Return a Django setting with fallback.
    """

    return getattr(
        settings,
        name,
        default,
    )


def get_positive_int_setting(
    name: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    """
    Read and clamp a positive integer setting.
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


def get_extraction_context() -> ExtractionContext:
    """
    Build extraction limits from Django settings.
    """

    return ExtractionContext(
        maximum_output_characters=get_positive_int_setting(
            "AIDEX_OCR_MAX_OUTPUT_CHARACTERS",
            DEFAULT_MAX_OUTPUT_CHARACTERS,
            maximum=5_000_000,
        ),
        maximum_text_bytes=get_positive_int_setting(
            "AIDEX_OCR_MAX_TEXT_BYTES",
            DEFAULT_MAX_TEXT_BYTES,
            maximum=100_000_000,
        ),
        maximum_pdf_pages=get_positive_int_setting(
            "AIDEX_OCR_MAX_PDF_PAGES",
            DEFAULT_MAX_PDF_PAGES,
            maximum=10_000,
        ),
        maximum_image_pixels=get_positive_int_setting(
            "AIDEX_OCR_MAX_IMAGE_PIXELS",
            DEFAULT_MAX_IMAGE_PIXELS,
            maximum=500_000_000,
        ),
        maximum_video_frames=get_positive_int_setting(
            "AIDEX_OCR_MAX_VIDEO_FRAMES",
            DEFAULT_MAX_VIDEO_FRAMES,
            maximum=500,
        ),
        video_frame_interval_seconds=get_positive_int_setting(
            "AIDEX_OCR_VIDEO_FRAME_INTERVAL_SECONDS",
            DEFAULT_VIDEO_FRAME_INTERVAL_SECONDS,
            maximum=3_600,
        ),
        maximum_archive_members=get_positive_int_setting(
            "AIDEX_OCR_MAX_ARCHIVE_MEMBERS",
            DEFAULT_MAX_ARCHIVE_MEMBERS,
            maximum=10_000,
        ),
        maximum_archive_member_bytes=get_positive_int_setting(
            "AIDEX_OCR_MAX_ARCHIVE_MEMBER_BYTES",
            DEFAULT_MAX_ARCHIVE_MEMBER_BYTES,
            maximum=1_000_000_000,
        ),
        maximum_total_archive_bytes=get_positive_int_setting(
            "AIDEX_OCR_MAX_TOTAL_ARCHIVE_BYTES",
            DEFAULT_MAX_TOTAL_ARCHIVE_BYTES,
            maximum=5_000_000_000,
        ),
        maximum_csv_rows=get_positive_int_setting(
            "AIDEX_OCR_MAX_CSV_ROWS",
            DEFAULT_MAX_CSV_ROWS,
            maximum=1_000_000,
        ),
        maximum_spreadsheet_rows=get_positive_int_setting(
            "AIDEX_OCR_MAX_SPREADSHEET_ROWS",
            DEFAULT_MAX_SPREADSHEET_ROWS,
            maximum=1_000_000,
        ),
        maximum_presentation_slides=get_positive_int_setting(
            "AIDEX_OCR_MAX_PRESENTATION_SLIDES",
            DEFAULT_MAX_PRESENTATION_SLIDES,
            maximum=10_000,
        ),
    )


# ==========================================================
# Generic Utilities
# ==========================================================

def normalize_whitespace(
    value: Any,
) -> str:
    """
    Normalize spaces while preserving readable paragraph breaks.
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

    normalized_lines: list[str] = []
    previous_blank = False

    for raw_line in text.splitlines():
        line = re.sub(
            r"[ \t]+",
            " ",
            raw_line,
        ).strip()

        is_blank = not line

        if is_blank and previous_blank:
            continue

        normalized_lines.append(
            line
        )

        previous_blank = is_blank

    return "\n".join(
        normalized_lines
    ).strip()


def truncate_text(
    value: Any,
    maximum_length: int,
) -> tuple[str, bool]:
    """
    Truncate text and return whether truncation occurred.
    """

    text = str(
        value or ""
    )

    if len(text) <= maximum_length:
        return text, False

    return (
        text[
            :maximum_length
        ],
        True,
    )


def safe_average(
    values: Iterable[float | None],
) -> float | None:
    """
    Return the average of available numeric values.
    """

    numeric_values = [
        float(value)
        for value in values
        if value is not None
    ]

    if not numeric_values:
        return None

    return sum(
        numeric_values
    ) / len(
        numeric_values
    )


def get_file_extension(
    evidence: Evidence,
) -> str:
    """
    Return normalized file extension.
    """

    explicit_extension = str(
        evidence.file_extension
        or ""
    ).strip().lower().lstrip(
        "."
    )

    if explicit_extension:
        return explicit_extension

    filename = str(
        evidence.original_filename
        or evidence.filename
        or ""
    )

    return Path(
        filename
    ).suffix.lower().lstrip(
        "."
    )


def get_mime_type(
    evidence: Evidence,
) -> str:
    """
    Guess evidence MIME type.
    """

    filename = str(
        evidence.original_filename
        or evidence.filename
        or ""
    )

    guessed_type, _ = mimetypes.guess_type(
        filename
    )

    return guessed_type or ""


def get_local_file_path(
    evidence: Evidence,
) -> str:
    """
    Return a short-lived decrypted evidence path for a registered extractor.
    """

    if not evidence.evidence_file:
        raise OCRFileAccessError(
            "Evidence does not contain an uploaded file."
        )

    temporary_paths = _ACTIVE_DECRYPTED_PATHS.get()
    if temporary_paths is None:
        raise OCRFileAccessError(
            (
                "Decrypted evidence paths may only be created inside the "
                "public extraction workflow."
            )
        )

    suffix = Path(
        evidence.original_filename
        or evidence.filename
        or ""
    ).suffix

    try:
        file_path = materialize_decrypted_file(
            evidence.evidence_file,
            suffix=suffix,
        )
    except (OSError, ValueError) as exc:
        raise OCRFileAccessError(
            "Evidence could not be authenticated and decrypted."
        ) from exc

    temporary_paths.append(file_path)

    return file_path


def read_bounded_bytes(
    file_path: str,
    maximum_bytes: int,
) -> tuple[bytes, bool]:
    """
    Read bounded bytes without loading the entire file.
    """

    with open(
        file_path,
        "rb",
    ) as file_handle:
        raw_bytes = file_handle.read(
            maximum_bytes + 1
        )

    truncated = len(
        raw_bytes
    ) > maximum_bytes

    if truncated:
        raw_bytes = raw_bytes[
            :maximum_bytes
        ]

    return raw_bytes, truncated


def decode_text_bytes(
    raw_bytes: bytes,
) -> tuple[str, str]:
    """
    Decode bytes using common encodings.
    """

    candidate_encodings = (
        "utf-8-sig",
        "utf-8",
        "utf-16",
        "latin-1",
    )

    for encoding in candidate_encodings:
        try:
            return (
                raw_bytes.decode(
                    encoding
                ),
                encoding,
            )
        except UnicodeDecodeError:
            continue

    return (
        raw_bytes.decode(
            "utf-8",
            errors="replace",
        ),
        "utf-8-replacement",
    )


def combine_segments(
    segments: Sequence[ExtractionSegment],
    *,
    maximum_characters: int,
) -> tuple[str, bool]:
    """
    Combine segments into a bounded readable text body.
    """

    output_parts: list[str] = []
    total_characters = 0
    truncated = False

    for segment in segments:
        header = (
            f"\n\n--- {segment.label} ---\n"
        )

        segment_text = normalize_whitespace(
            segment.text
        )

        candidate = (
            header
            + segment_text
        )

        remaining = (
            maximum_characters
            - total_characters
        )

        if remaining <= 0:
            truncated = True
            break

        if len(candidate) > remaining:
            output_parts.append(
                candidate[
                    :remaining
                ]
            )
            truncated = True
            break

        output_parts.append(
            candidate
        )
        total_characters += len(
            candidate
        )

    return (
        normalize_whitespace(
            "".join(
                output_parts
            )
        ),
        truncated,
    )


def build_result(
    *,
    extractor_name: str,
    source_extension: str,
    mime_type: str,
    segments: Sequence[ExtractionSegment],
    warnings: Sequence[ExtractionWarning] = (),
    metadata: Mapping[str, Any] | None = None,
    maximum_characters: int,
) -> ExtractionResult:
    """
    Build a normalized ExtractionResult from segments.
    """

    text, truncated = combine_segments(
        segments,
        maximum_characters=maximum_characters,
    )

    confidence = safe_average(
        segment.confidence
        for segment in segments
    )

    return ExtractionResult(
        text=text,
        extractor_name=extractor_name,
        source_extension=source_extension,
        mime_type=mime_type,
        character_count=len(
            text
        ),
        truncated=truncated,
        confidence=confidence,
        segments=list(
            segments
        ),
        warnings=list(
            warnings
        ),
        metadata=dict(
            metadata or {}
        ),
    )


# ==========================================================
# Base Extractor
# ==========================================================

class BaseExtractor(ABC):
    """
    Abstract base class for evidence extractors.
    """

    name = "base"
    supported_extensions: set[str] = set()

    def supports(
        self,
        evidence: Evidence,
    ) -> bool:
        """
        Return whether this extractor supports the evidence.
        """

        return get_file_extension(
            evidence
        ) in self.supported_extensions

    @abstractmethod
    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:
        """
        Extract text and metadata from evidence.
        """

        raise NotImplementedError


# ==========================================================
# Plain Text Extractor
# ==========================================================

class PlainTextExtractor(BaseExtractor):
    """
    Extract bounded plain text and log files.
    """

    name = "plain_text"

    supported_extensions = (
        TEXT_EXTENSIONS
    )

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        file_path = get_local_file_path(
            evidence
        )

        raw_bytes, file_truncated = read_bounded_bytes(
            file_path,
            context.maximum_text_bytes,
        )

        decoded_text, encoding = decode_text_bytes(
            raw_bytes
        )

        normalized_text = normalize_whitespace(
            decoded_text
        )

        warnings: list[ExtractionWarning] = []

        if file_truncated:
            warnings.append(
                ExtractionWarning(
                    code="TEXT_FILE_TRUNCATED",
                    message=(
                        "Text extraction was limited by the configured "
                        "maximum byte count."
                    ),
                    details={
                        "maximum_bytes": (
                            context.maximum_text_bytes
                        ),
                    },
                )
            )

        segment = ExtractionSegment(
            label="Text Content",
            text=normalized_text,
            source_type="text",
            sequence=1,
            metadata={
                "encoding": encoding,
            },
        )

        return build_result(
            extractor_name=self.name,
            source_extension=get_file_extension(
                evidence
            ),
            mime_type=get_mime_type(
                evidence
            ),
            segments=[
                segment
            ],
            warnings=warnings,
            metadata={
                "encoding": encoding,
                "source_file_truncated": file_truncated,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# CSV Extractor
# ==========================================================

class CSVExtractor(BaseExtractor):
    """
    Extract bounded CSV rows into readable text.
    """

    name = "csv"

    supported_extensions = {
        "csv",
    }

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        file_path = get_local_file_path(
            evidence
        )

        raw_bytes, file_truncated = read_bounded_bytes(
            file_path,
            context.maximum_text_bytes,
        )

        decoded_text, encoding = decode_text_bytes(
            raw_bytes
        )

        stream = io.StringIO(
            decoded_text
        )

        try:
            dialect = csv.Sniffer().sniff(
                decoded_text[
                    :10_000
                ]
            )
        except csv.Error:
            dialect = csv.excel

        reader = csv.reader(
            stream,
            dialect,
        )

        rows: list[list[str]] = []
        row_limit_reached = False

        for index, row in enumerate(
            reader,
            start=1,
        ):
            if index > context.maximum_csv_rows:
                row_limit_reached = True
                break

            rows.append(
                [
                    normalize_whitespace(
                        cell
                    )
                    for cell in row
                ]
            )

        rendered_rows = [
            " | ".join(
                row
            )
            for row in rows
        ]

        warnings: list[ExtractionWarning] = []

        if file_truncated:
            warnings.append(
                ExtractionWarning(
                    code="CSV_FILE_TRUNCATED",
                    message=(
                        "CSV bytes were truncated before parsing."
                    ),
                )
            )

        if row_limit_reached:
            warnings.append(
                ExtractionWarning(
                    code="CSV_ROW_LIMIT_REACHED",
                    message=(
                        "CSV extraction stopped at the configured row limit."
                    ),
                    details={
                        "maximum_rows": (
                            context.maximum_csv_rows
                        ),
                    },
                )
            )

        segment = ExtractionSegment(
            label="CSV Rows",
            text="\n".join(
                rendered_rows
            ),
            source_type="csv",
            sequence=1,
            metadata={
                "row_count": len(
                    rows
                ),
                "encoding": encoding,
            },
        )

        return build_result(
            extractor_name=self.name,
            source_extension="csv",
            mime_type=get_mime_type(
                evidence
            ),
            segments=[
                segment
            ],
            warnings=warnings,
            metadata={
                "row_count": len(
                    rows
                ),
                "encoding": encoding,
                "source_file_truncated": file_truncated,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# JSON Extractor
# ==========================================================

class JSONExtractor(BaseExtractor):
    """
    Parse and normalize bounded JSON evidence.
    """

    name = "json"

    supported_extensions = {
        "json",
    }

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        file_path = get_local_file_path(
            evidence
        )

        raw_bytes, file_truncated = read_bounded_bytes(
            file_path,
            context.maximum_text_bytes,
        )

        decoded_text, encoding = decode_text_bytes(
            raw_bytes
        )

        warnings: list[ExtractionWarning] = []

        try:
            parsed_json = json.loads(
                decoded_text
            )

            rendered_text = json.dumps(
                parsed_json,
                ensure_ascii=False,
                indent=2,
            )

        except json.JSONDecodeError:
            rendered_text = normalize_whitespace(
                decoded_text
            )

            warnings.append(
                ExtractionWarning(
                    code="INVALID_JSON",
                    message=(
                        "JSON parsing failed. Raw text was preserved instead."
                    ),
                )
            )

        if file_truncated:
            warnings.append(
                ExtractionWarning(
                    code="JSON_FILE_TRUNCATED",
                    message=(
                        "JSON bytes were truncated before parsing."
                    ),
                )
            )

        segment = ExtractionSegment(
            label="JSON Content",
            text=rendered_text,
            source_type="json",
            sequence=1,
            metadata={
                "encoding": encoding,
            },
        )

        return build_result(
            extractor_name=self.name,
            source_extension="json",
            mime_type=get_mime_type(
                evidence
            ),
            segments=[
                segment
            ],
            warnings=warnings,
            metadata={
                "encoding": encoding,
                "source_file_truncated": file_truncated,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# XML Extractor
# ==========================================================

class XMLExtractor(BaseExtractor):
    """
    Extract bounded XML as normalized text.
    """

    name = "xml"

    supported_extensions = {
        "xml",
    }

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        file_path = get_local_file_path(
            evidence
        )

        raw_bytes, file_truncated = read_bounded_bytes(
            file_path,
            context.maximum_text_bytes,
        )

        decoded_text, encoding = decode_text_bytes(
            raw_bytes
        )

        warnings: list[ExtractionWarning] = []

        if file_truncated:
            warnings.append(
                ExtractionWarning(
                    code="XML_FILE_TRUNCATED",
                    message=(
                        "XML bytes were truncated before extraction."
                    ),
                )
            )

        segment = ExtractionSegment(
            label="XML Content",
            text=normalize_whitespace(
                decoded_text
            ),
            source_type="xml",
            sequence=1,
            metadata={
                "encoding": encoding,
            },
        )

        return build_result(
            extractor_name=self.name,
            source_extension="xml",
            mime_type=get_mime_type(
                evidence
            ),
            segments=[
                segment
            ],
            warnings=warnings,
            metadata={
                "encoding": encoding,
                "source_file_truncated": file_truncated,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# PDF Extractor
# ==========================================================

class PDFExtractor(BaseExtractor):
    """
    Extract text page-by-page using pypdf.
    """

    name = "pdf"

    supported_extensions = PDF_EXTENSIONS

    def _import_dependency(self):
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "PDF extraction requires pypdf. "
                    "Install it with: pip install pypdf"
                )
            ) from exc

        return PdfReader

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        PdfReader = self._import_dependency()

        file_path = get_local_file_path(
            evidence
        )

        try:
            reader = PdfReader(
                file_path
            )
        except Exception as exc:
            raise OCRCorruptedFileError(
                "PDF could not be opened or parsed."
            ) from exc

        page_count = len(
            reader.pages
        )

        pages_to_process = min(
            page_count,
            context.maximum_pdf_pages,
        )

        segments: list[ExtractionSegment] = []
        warnings: list[ExtractionWarning] = []

        for page_index in range(
            pages_to_process
        ):
            page = reader.pages[
                page_index
            ]

            try:
                page_text = page.extract_text() or ""
            except Exception as exc:
                warnings.append(
                    ExtractionWarning(
                        code="PDF_PAGE_EXTRACTION_FAILED",
                        message=(
                            f"Text extraction failed for PDF page "
                            f"{page_index + 1}."
                        ),
                        details={
                            "error_type": (
                                exc.__class__.__name__
                            ),
                        },
                    )
                )
                page_text = ""

            segments.append(
                ExtractionSegment(
                    label=f"PDF Page {page_index + 1}",
                    text=normalize_whitespace(
                        page_text
                    ),
                    source_type="pdf_page",
                    sequence=page_index + 1,
                    metadata={
                        "page_number": (
                            page_index + 1
                        ),
                    },
                )
            )

        if page_count > pages_to_process:
            warnings.append(
                ExtractionWarning(
                    code="PDF_PAGE_LIMIT_REACHED",
                    message=(
                        "PDF extraction stopped at the configured page limit."
                    ),
                    details={
                        "total_pages": page_count,
                        "processed_pages": (
                            pages_to_process
                        ),
                    },
                )
            )

        if not any(
            segment.text
            for segment in segments
        ):
            warnings.append(
                ExtractionWarning(
                    code="PDF_NO_EXTRACTABLE_TEXT",
                    message=(
                        "No embedded PDF text was found. "
                        "Image OCR may be required."
                    ),
                )
            )

        return build_result(
            extractor_name=self.name,
            source_extension="pdf",
            mime_type=get_mime_type(
                evidence
            ),
            segments=segments,
            warnings=warnings,
            metadata={
                "total_pages": page_count,
                "processed_pages": pages_to_process,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# Image OCR Extractor
# ==========================================================

class ImageOCRExtractor(BaseExtractor):
    """
    Perform local image OCR using Pillow and pytesseract.
    """

    name = "image_ocr"

    supported_extensions = IMAGE_EXTENSIONS

    def _import_dependencies(self):
        try:
            from PIL import Image
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "Image OCR requires Pillow. "
                    "Install it with: pip install pillow"
                )
            ) from exc

        try:
            import pytesseract
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "Image OCR requires pytesseract. "
                    "Install it with: pip install pytesseract"
                )
            ) from exc

        return Image, pytesseract

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        Image, pytesseract = self._import_dependencies()

        file_path = get_local_file_path(
            evidence
        )

        tesseract_command = str(
            get_setting(
                "AIDEX_TESSERACT_CMD",
                "",
            )
            or ""
        ).strip()

        if tesseract_command:
            pytesseract.pytesseract.tesseract_cmd = (
                tesseract_command
            )

        try:
            image = Image.open(
                file_path
            )
        except Exception as exc:
            raise OCRCorruptedFileError(
                "Image could not be opened."
            ) from exc

        width, height = image.size
        pixel_count = width * height

        if pixel_count > context.maximum_image_pixels:
            raise OCRFileTooLargeError(
                (
                    "Image exceeds the configured pixel limit. "
                    "Resize or preprocess it before OCR."
                )
            )

        language = str(
            get_setting(
                "AIDEX_TESSERACT_LANGUAGE",
                "eng",
            )
            or "eng"
        ).strip()

        configuration = str(
            get_setting(
                "AIDEX_TESSERACT_CONFIG",
                "--psm 3",
            )
            or "--psm 3"
        ).strip()

        warnings: list[ExtractionWarning] = []

        try:
            data = pytesseract.image_to_data(
                image,
                lang=language,
                config=configuration,
                output_type=(
                    pytesseract.Output.DICT
                ),
            )
        except Exception as exc:
            raise OCRExtractionError(
                (
                    "Tesseract OCR execution failed. "
                    "Confirm that Tesseract is installed and configured."
                )
            ) from exc

        tokens: list[str] = []
        confidences: list[float] = []

        text_values = data.get(
            "text",
            []
        )

        confidence_values = data.get(
            "conf",
            []
        )

        for raw_text, raw_confidence in zip(
            text_values,
            confidence_values,
        ):
            token = normalize_whitespace(
                raw_text
            )

            if not token:
                continue

            tokens.append(
                token
            )

            try:
                confidence_value = float(
                    raw_confidence
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

            if confidence_value >= 0:
                confidences.append(
                    confidence_value
                )

        extracted_text = " ".join(
            tokens
        )

        confidence = safe_average(
            confidences
        )

        if not extracted_text:
            warnings.append(
                ExtractionWarning(
                    code="IMAGE_NO_TEXT",
                    message=(
                        "No readable text was detected in the image."
                    ),
                )
            )

        segment = ExtractionSegment(
            label="Image OCR",
            text=extracted_text,
            source_type="image_ocr",
            sequence=1,
            confidence=confidence,
            metadata={
                "width": width,
                "height": height,
                "pixel_count": pixel_count,
                "language": language,
                "configuration": configuration,
            },
        )

        return build_result(
            extractor_name=self.name,
            source_extension=get_file_extension(
                evidence
            ),
            mime_type=get_mime_type(
                evidence
            ),
            segments=[
                segment
            ],
            warnings=warnings,
            metadata={
                "width": width,
                "height": height,
                "pixel_count": pixel_count,
                "language": language,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# DOCX Extractor
# ==========================================================

class DOCXExtractor(BaseExtractor):
    """
    Extract paragraphs and table text from DOCX.
    """

    name = "docx"

    supported_extensions = WORD_EXTENSIONS

    def _import_dependency(self):
        try:
            from docx import Document
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "DOCX extraction requires python-docx. "
                    "Install it with: pip install python-docx"
                )
            ) from exc

        return Document

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        Document = self._import_dependency()

        file_path = get_local_file_path(
            evidence
        )

        try:
            document = Document(
                file_path
            )
        except Exception as exc:
            raise OCRCorruptedFileError(
                "DOCX file could not be opened."
            ) from exc

        segments: list[ExtractionSegment] = []
        sequence = 1

        paragraph_text = "\n".join(
            normalize_whitespace(
                paragraph.text
            )
            for paragraph in document.paragraphs
            if normalize_whitespace(
                paragraph.text
            )
        )

        if paragraph_text:
            segments.append(
                ExtractionSegment(
                    label="Document Paragraphs",
                    text=paragraph_text,
                    source_type="docx_paragraphs",
                    sequence=sequence,
                )
            )
            sequence += 1

        for table_index, table in enumerate(
            document.tables,
            start=1,
        ):
            rendered_rows: list[str] = []

            for row in table.rows:
                rendered_rows.append(
                    " | ".join(
                        normalize_whitespace(
                            cell.text
                        )
                        for cell in row.cells
                    )
                )

            segments.append(
                ExtractionSegment(
                    label=f"Table {table_index}",
                    text="\n".join(
                        rendered_rows
                    ),
                    source_type="docx_table",
                    sequence=sequence,
                    metadata={
                        "table_number": table_index,
                    },
                )
            )
            sequence += 1

        warnings: list[ExtractionWarning] = []

        if not segments:
            warnings.append(
                ExtractionWarning(
                    code="DOCX_NO_TEXT",
                    message=(
                        "No extractable paragraph or table text was found."
                    ),
                )
            )

        return build_result(
            extractor_name=self.name,
            source_extension="docx",
            mime_type=get_mime_type(
                evidence
            ),
            segments=segments,
            warnings=warnings,
            metadata={
                "paragraph_count": len(
                    document.paragraphs
                ),
                "table_count": len(
                    document.tables
                ),
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# XLSX Extractor
# ==========================================================

class XLSXExtractor(BaseExtractor):
    """
    Extract bounded spreadsheet rows using openpyxl.
    """

    name = "xlsx"

    supported_extensions = SPREADSHEET_EXTENSIONS

    def _import_dependency(self):
        try:
            from openpyxl import load_workbook
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "XLSX extraction requires openpyxl. "
                    "Install it with: pip install openpyxl"
                )
            ) from exc

        return load_workbook

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        load_workbook = self._import_dependency()

        file_path = get_local_file_path(
            evidence
        )

        try:
            workbook = load_workbook(
                filename=file_path,
                read_only=True,
                data_only=True,
            )
        except Exception as exc:
            raise OCRCorruptedFileError(
                "XLSX file could not be opened."
            ) from exc

        segments: list[ExtractionSegment] = []
        warnings: list[ExtractionWarning] = []
        processed_rows = 0

        for sheet_index, worksheet in enumerate(
            workbook.worksheets,
            start=1,
        ):
            rendered_rows: list[str] = []

            for row in worksheet.iter_rows(
                values_only=True
            ):
                if processed_rows >= (
                    context.maximum_spreadsheet_rows
                ):
                    break

                rendered_rows.append(
                    " | ".join(
                        normalize_whitespace(
                            value
                        )
                        for value in row
                    )
                )

                processed_rows += 1

            segments.append(
                ExtractionSegment(
                    label=f"Worksheet: {worksheet.title}",
                    text="\n".join(
                        rendered_rows
                    ),
                    source_type="xlsx_sheet",
                    sequence=sheet_index,
                    metadata={
                        "worksheet_title": (
                            worksheet.title
                        ),
                        "rows_extracted": len(
                            rendered_rows
                        ),
                    },
                )
            )

            if processed_rows >= (
                context.maximum_spreadsheet_rows
            ):
                warnings.append(
                    ExtractionWarning(
                        code="XLSX_ROW_LIMIT_REACHED",
                        message=(
                            "Spreadsheet extraction stopped at the configured "
                            "row limit."
                        ),
                        details={
                            "maximum_rows": (
                                context.maximum_spreadsheet_rows
                            ),
                        },
                    )
                )
                break

        workbook.close()

        return build_result(
            extractor_name=self.name,
            source_extension="xlsx",
            mime_type=get_mime_type(
                evidence
            ),
            segments=segments,
            warnings=warnings,
            metadata={
                "worksheet_count": len(
                    segments
                ),
                "processed_rows": processed_rows,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# PPTX Extractor
# ==========================================================

class PPTXExtractor(BaseExtractor):
    """
    Extract text from PowerPoint slides.
    """

    name = "pptx"

    supported_extensions = PRESENTATION_EXTENSIONS

    def _import_dependency(self):
        try:
            from pptx import Presentation
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "PPTX extraction requires python-pptx. "
                    "Install it with: pip install python-pptx"
                )
            ) from exc

        return Presentation

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        Presentation = self._import_dependency()

        file_path = get_local_file_path(
            evidence
        )

        try:
            presentation = Presentation(
                file_path
            )
        except Exception as exc:
            raise OCRCorruptedFileError(
                "PPTX file could not be opened."
            ) from exc

        slide_count = len(
            presentation.slides
        )

        slides_to_process = min(
            slide_count,
            context.maximum_presentation_slides,
        )

        segments: list[ExtractionSegment] = []
        warnings: list[ExtractionWarning] = []

        for slide_index in range(
            slides_to_process
        ):
            slide = presentation.slides[
                slide_index
            ]

            text_parts: list[str] = []

            for shape in slide.shapes:
                text = getattr(
                    shape,
                    "text",
                    "",
                )

                normalized_text = normalize_whitespace(
                    text
                )

                if normalized_text:
                    text_parts.append(
                        normalized_text
                    )

            segments.append(
                ExtractionSegment(
                    label=f"Slide {slide_index + 1}",
                    text="\n".join(
                        text_parts
                    ),
                    source_type="pptx_slide",
                    sequence=slide_index + 1,
                    metadata={
                        "slide_number": (
                            slide_index + 1
                        ),
                    },
                )
            )

        if slide_count > slides_to_process:
            warnings.append(
                ExtractionWarning(
                    code="PPTX_SLIDE_LIMIT_REACHED",
                    message=(
                        "Presentation extraction stopped at the configured "
                        "slide limit."
                    ),
                    details={
                        "total_slides": slide_count,
                        "processed_slides": (
                            slides_to_process
                        ),
                    },
                )
            )

        return build_result(
            extractor_name=self.name,
            source_extension="pptx",
            mime_type=get_mime_type(
                evidence
            ),
            segments=segments,
            warnings=warnings,
            metadata={
                "total_slides": slide_count,
                "processed_slides": slides_to_process,
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# ZIP Extractor
# ==========================================================

class ZIPExtractor(BaseExtractor):
    """
    Safely inspect bounded text-like members inside ZIP archives.

    This extractor does not execute files and does not recursively unpack
    nested archives.
    """

    name = "zip"

    supported_extensions = ARCHIVE_EXTENSIONS

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        file_path = get_local_file_path(
            evidence
        )

        try:
            archive = zipfile.ZipFile(
                file_path
            )
        except (
            OSError,
            zipfile.BadZipFile,
        ) as exc:
            raise OCRCorruptedFileError(
                "ZIP archive could not be opened."
            ) from exc

        segments: list[ExtractionSegment] = []
        warnings: list[ExtractionWarning] = []

        total_uncompressed_bytes = 0
        processed_members = 0

        archive_members = archive.infolist()

        for member in archive_members:
            if processed_members >= (
                context.maximum_archive_members
            ):
                warnings.append(
                    ExtractionWarning(
                        code="ZIP_MEMBER_LIMIT_REACHED",
                        message=(
                            "Archive extraction stopped at the configured "
                            "member limit."
                        ),
                    )
                )
                break

            if member.is_dir():
                continue

            member_path = Path(
                member.filename
            )

            member_extension = (
                member_path.suffix
                .lower()
                .lstrip(
                    "."
                )
            )

            if member.file_size > (
                context.maximum_archive_member_bytes
            ):
                warnings.append(
                    ExtractionWarning(
                        code="ZIP_MEMBER_TOO_LARGE",
                        message=(
                            f"Skipped large archive member: {member.filename}"
                        ),
                        details={
                            "file_size": member.file_size,
                        },
                    )
                )
                continue

            if (
                total_uncompressed_bytes
                + member.file_size
                > context.maximum_total_archive_bytes
            ):
                warnings.append(
                    ExtractionWarning(
                        code="ZIP_TOTAL_LIMIT_REACHED",
                        message=(
                            "Archive extraction stopped at the configured "
                            "total uncompressed byte limit."
                        ),
                    )
                )
                break

            if member_extension not in (
                TEXT_EXTENSIONS
                | STRUCTURED_TEXT_EXTENSIONS
            ):
                continue

            try:
                raw_bytes = archive.read(
                    member
                )
            except Exception as exc:
                warnings.append(
                    ExtractionWarning(
                        code="ZIP_MEMBER_READ_FAILED",
                        message=(
                            f"Could not read archive member: "
                            f"{member.filename}"
                        ),
                        details={
                            "error_type": (
                                exc.__class__.__name__
                            ),
                        },
                    )
                )
                continue

            decoded_text, encoding = decode_text_bytes(
                raw_bytes
            )

            segments.append(
                ExtractionSegment(
                    label=f"Archive Member: {member.filename}",
                    text=normalize_whitespace(
                        decoded_text
                    ),
                    source_type="zip_member",
                    sequence=processed_members + 1,
                    metadata={
                        "member_name": (
                            member.filename
                        ),
                        "file_size": (
                            member.file_size
                        ),
                        "encoding": encoding,
                    },
                )
            )

            processed_members += 1
            total_uncompressed_bytes += (
                member.file_size
            )

        archive.close()

        if not segments:
            warnings.append(
                ExtractionWarning(
                    code="ZIP_NO_TEXT_MEMBERS",
                    message=(
                        "No supported text-like members were extracted "
                        "from the archive."
                    ),
                )
            )

        return build_result(
            extractor_name=self.name,
            source_extension="zip",
            mime_type=get_mime_type(
                evidence
            ),
            segments=segments,
            warnings=warnings,
            metadata={
                "archive_member_count": len(
                    archive_members
                ),
                "processed_members": (
                    processed_members
                ),
                "processed_uncompressed_bytes": (
                    total_uncompressed_bytes
                ),
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# Video Frame OCR Extractor
# ==========================================================

class VideoFrameOCRExtractor(BaseExtractor):
    """
    Extract a bounded set of video frames and run local OCR.

    This is intentionally conservative and should be executed in a background
    worker for large videos.
    """

    name = "video_frame_ocr"

    supported_extensions = VIDEO_EXTENSIONS

    def _import_dependencies(self):
        try:
            import cv2
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "Video frame extraction requires OpenCV. "
                    "Install it with: pip install opencv-python"
                )
            ) from exc

        try:
            from PIL import Image
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "Video OCR requires Pillow. "
                    "Install it with: pip install pillow"
                )
            ) from exc

        try:
            import pytesseract
        except ImportError as exc:
            raise OCRDependencyError(
                (
                    "Video OCR requires pytesseract. "
                    "Install it with: pip install pytesseract"
                )
            ) from exc

        return cv2, Image, pytesseract

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        cv2, Image, pytesseract = (
            self._import_dependencies()
        )

        file_path = get_local_file_path(
            evidence
        )

        capture = cv2.VideoCapture(
            file_path
        )

        if not capture.isOpened():
            raise OCRCorruptedFileError(
                "Video could not be opened."
            )

        frames_per_second = capture.get(
            cv2.CAP_PROP_FPS
        ) or 0

        total_frames = int(
            capture.get(
                cv2.CAP_PROP_FRAME_COUNT
            )
            or 0
        )

        duration_seconds = (
            total_frames / frames_per_second
            if frames_per_second > 0
            else 0
        )

        interval_seconds = (
            context.video_frame_interval_seconds
        )

        target_times: list[float] = []

        current_time = 0.0

        while (
            current_time <= duration_seconds
            and len(target_times)
            < context.maximum_video_frames
        ):
            target_times.append(
                current_time
            )
            current_time += interval_seconds

        if not target_times:
            target_times = [
                0.0
            ]

        segments: list[ExtractionSegment] = []
        warnings: list[ExtractionWarning] = []

        for index, target_time in enumerate(
            target_times,
            start=1,
        ):
            capture.set(
                cv2.CAP_PROP_POS_MSEC,
                target_time * 1_000,
            )

            success, frame = capture.read()

            if not success:
                warnings.append(
                    ExtractionWarning(
                        code="VIDEO_FRAME_READ_FAILED",
                        message=(
                            f"Could not read video frame near "
                            f"{target_time:.2f} seconds."
                        ),
                    )
                )
                continue

            frame_rgb = cv2.cvtColor(
                frame,
                cv2.COLOR_BGR2RGB,
            )

            image = Image.fromarray(
                frame_rgb
            )

            try:
                frame_text = pytesseract.image_to_string(
                    image,
                    lang=str(
                        get_setting(
                            "AIDEX_TESSERACT_LANGUAGE",
                            "eng",
                        )
                        or "eng"
                    ),
                    config=str(
                        get_setting(
                            "AIDEX_TESSERACT_CONFIG",
                            "--psm 3",
                        )
                        or "--psm 3"
                    ),
                )
            except Exception as exc:
                warnings.append(
                    ExtractionWarning(
                        code="VIDEO_FRAME_OCR_FAILED",
                        message=(
                            f"OCR failed for frame near "
                            f"{target_time:.2f} seconds."
                        ),
                        details={
                            "error_type": (
                                exc.__class__.__name__
                            ),
                        },
                    )
                )
                frame_text = ""

            segments.append(
                ExtractionSegment(
                    label=(
                        f"Video Frame at "
                        f"{target_time:.2f} seconds"
                    ),
                    text=normalize_whitespace(
                        frame_text
                    ),
                    source_type="video_frame_ocr",
                    sequence=index,
                    metadata={
                        "timestamp_seconds": (
                            target_time
                        ),
                    },
                )
            )

        capture.release()

        if not any(
            segment.text
            for segment in segments
        ):
            warnings.append(
                ExtractionWarning(
                    code="VIDEO_NO_TEXT",
                    message=(
                        "No readable text was detected in sampled video frames."
                    ),
                )
            )

        return build_result(
            extractor_name=self.name,
            source_extension=get_file_extension(
                evidence
            ),
            mime_type=get_mime_type(
                evidence
            ),
            segments=segments,
            warnings=warnings,
            metadata={
                "fps": frames_per_second,
                "total_frames": total_frames,
                "duration_seconds": duration_seconds,
                "sampled_frames": len(
                    segments
                ),
                "frame_interval_seconds": (
                    interval_seconds
                ),
            },
            maximum_characters=(
                context.maximum_output_characters
            ),
        )


# ==========================================================
# Audio Placeholder Extractor
# ==========================================================

class AudioTranscriptionPlaceholderExtractor(BaseExtractor):
    """
    Explicit placeholder for future audio transcription.

    No fake transcription is produced.
    """

    name = "audio_transcription_placeholder"

    supported_extensions = AUDIO_EXTENSIONS

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        warning = ExtractionWarning(
            code="AUDIO_TRANSCRIPTION_NOT_CONFIGURED",
            message=(
                "Audio transcription is not configured. "
                "Integrate a local speech-to-text engine before AI analysis."
            ),
        )

        return ExtractionResult(
            text="",
            extractor_name=self.name,
            source_extension=get_file_extension(
                evidence
            ),
            mime_type=get_mime_type(
                evidence
            ),
            character_count=0,
            truncated=False,
            confidence=None,
            segments=[],
            warnings=[
                warning
            ],
            metadata={
                "transcription_configured": False,
            },
        )


# ==========================================================
# Unsupported Binary Placeholder
# ==========================================================

class UnsupportedBinaryExtractor(BaseExtractor):
    """
    Explicitly reject unsupported legacy or archive formats.
    """

    name = "unsupported_binary"

    supported_extensions = BINARY_ONLY_EXTENSIONS

    def extract(
        self,
        evidence: Evidence,
        *,
        context: ExtractionContext,
    ) -> ExtractionResult:

        extension = get_file_extension(
            evidence
        )

        raise OCRUnsupportedFileError(
            (
                f"Extraction for .{extension} files is not configured. "
                "Convert the file to a supported modern format first."
            )
        )


# ==========================================================
# Extractor Registry
# ==========================================================

EXTRACTOR_REGISTRY: list[BaseExtractor] = [
    PlainTextExtractor(),
    CSVExtractor(),
    JSONExtractor(),
    XMLExtractor(),
    PDFExtractor(),
    ImageOCRExtractor(),
    DOCXExtractor(),
    XLSXExtractor(),
    PPTXExtractor(),
    ZIPExtractor(),
    VideoFrameOCRExtractor(),
    AudioTranscriptionPlaceholderExtractor(),
    UnsupportedBinaryExtractor(),
]


def register_extractor(
    extractor: BaseExtractor,
    *,
    prepend: bool = False,
) -> None:
    """
    Register a custom extractor.
    """

    if not isinstance(
        extractor,
        BaseExtractor,
    ):
        raise OCRConfigurationError(
            "Extractor must inherit from BaseExtractor."
        )

    if prepend:
        EXTRACTOR_REGISTRY.insert(
            0,
            extractor,
        )
    else:
        EXTRACTOR_REGISTRY.append(
            extractor
        )


def get_extractor_for_evidence(
    evidence: Evidence,
) -> BaseExtractor:
    """
    Return the first matching extractor.
    """

    for extractor in EXTRACTOR_REGISTRY:
        if extractor.supports(
            evidence
        ):
            return extractor

    extension = get_file_extension(
        evidence
    )

    raise OCRUnsupportedFileError(
        (
            f"No extractor is registered for "
            f".{extension or 'unknown'} evidence."
        )
    )


def list_supported_extensions() -> list[str]:
    """
    Return all registered extensions.
    """

    extensions: set[str] = set()

    for extractor in EXTRACTOR_REGISTRY:
        extensions.update(
            extractor.supported_extensions
        )

    return sorted(
        extensions
    )


# ==========================================================
# Public Extraction API
# ==========================================================

@cleanup_decrypted_evidence_paths
def extract_evidence_content(
    evidence: Evidence,
    *,
    context: ExtractionContext | None = None,
) -> ExtractionResult:
    """
    Extract safe derived content from one evidence record.
    """

    if evidence is None:
        raise OCRConfigurationError(
            "Evidence instance is required."
        )

    if not evidence.is_active:
        raise OCRFileAccessError(
            "Archived evidence cannot be extracted."
        )

    if not evidence.evidence_file:
        raise OCRFileAccessError(
            "Evidence does not contain a file."
        )

    extraction_context = (
        context
        or get_extraction_context()
    )

    extractor = get_extractor_for_evidence(
        evidence
    )

    logger.info(
        "Starting extraction for evidence %s using %s.",
        evidence.pk,
        extractor.name,
    )

    try:
        result = extractor.extract(
            evidence,
            context=extraction_context,
        )
    except OCRServiceError:
        raise
    except Exception as exc:
        logger.exception(
            "Unexpected extraction failure for evidence %s.",
            evidence.pk,
        )

        raise OCRExtractionError(
            (
                f"Unexpected extraction failure using "
                f"'{extractor.name}'."
            )
        ) from exc

    result.metadata.update({
        "evidence_id": str(
            evidence.pk
        ),
        "evidence_title": (
            evidence.evidence_title
        ),
        "case_number": (
            evidence.case.case_number
        ),
        "sha256_hash": (
            evidence.sha256_hash
        ),
        "verification_status": (
            evidence.verification_status
        ),
    })

    logger.info(
        (
            "Extraction completed for evidence %s: "
            "%s characters, %s segments, %s warnings."
        ),
        evidence.pk,
        result.character_count,
        result.segment_count,
        result.warning_count,
    )

    return result


def extract_evidence_text(
    evidence: Evidence,
) -> str:
    """
    Convenience helper returning extracted text only.
    """

    return extract_evidence_content(
        evidence
    ).text


def build_ai_ready_extraction(
    evidence: Evidence,
) -> dict[str, Any]:
    """
    Return service-ready extraction content and metadata.
    """

    result = extract_evidence_content(
        evidence
    )

    return {
        "text": result.text,
        "confidence": result.confidence,
        "extractor_name": result.extractor_name,
        "truncated": result.truncated,
        "warnings": [
            warning.as_dict()
            for warning in result.warnings
        ],
        "metadata": result.metadata,
        "segments": [
            segment.as_dict()
            for segment in result.segments
        ],
    }


def get_extraction_health() -> dict[str, Any]:
    """
    Report locally available extraction dependencies without processing files.
    """

    dependency_status: dict[str, dict[str, Any]] = {}

    optional_dependencies = {
        "pypdf": "pypdf",
        "Pillow": "PIL",
        "pytesseract": "pytesseract",
        "python-docx": "docx",
        "openpyxl": "openpyxl",
        "python-pptx": "pptx",
        "opencv-python": "cv2",
    }

    import importlib.util

    for package_name, module_name in (
        optional_dependencies.items()
    ):
        available = (
            importlib.util.find_spec(
                module_name
            )
            is not None
        )

        dependency_status[
            package_name
        ] = {
            "available": available,
            "module": module_name,
        }

    return {
        "supported_extensions": (
            list_supported_extensions()
        ),
        "dependencies": dependency_status,
        "context": {
            "maximum_output_characters": (
                get_extraction_context()
                .maximum_output_characters
            ),
            "maximum_text_bytes": (
                get_extraction_context()
                .maximum_text_bytes
            ),
            "maximum_pdf_pages": (
                get_extraction_context()
                .maximum_pdf_pages
            ),
            "maximum_video_frames": (
                get_extraction_context()
                .maximum_video_frames
            ),
        },
    }
