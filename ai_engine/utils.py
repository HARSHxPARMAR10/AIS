"""
AIDEX File Validation and Metadata Utilities

This module provides reusable utilities for:

- Evidence file validation
- File extension validation
- File-size validation
- Secure filename generation
- MIME-type detection
- Evidence category detection
- File metadata extraction
- Django uploaded-file validation

Important:
MIME detection in this module is based on the filename extension.
Actual file-signature validation can be added later using a dedicated
content-inspection library.
"""

from __future__ import annotations

import mimetypes
import os
import re
import unicodedata
import uuid

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Final

from .config import (
    ALLOWED_AUDIO_EXTENSIONS,
    ALLOWED_DOCUMENT_EXTENSIONS,
    ALLOWED_IMAGE_EXTENSIONS,
    ALLOWED_VIDEO_EXTENSIONS,
    ALLOW_EXECUTABLE_FILES,
    ENABLE_FILE_VALIDATION,
    MAX_FILE_SIZE,
    SUPPORTED_EXTENSIONS,
)


MAX_FILENAME_LENGTH: Final[int] = 255

DANGEROUS_EXTENSIONS: Final[set[str]] = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".sh",
    ".dll",
    ".sys",
}

SAFE_FILENAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[^A-Za-z0-9._-]+"
)


class FileValidationError(Exception):
    """
    Base exception raised when evidence file validation fails.
    """


class UnsupportedFileTypeError(FileValidationError):
    """
    Raised when the file extension is not supported.
    """


class InvalidFileSizeError(FileValidationError):
    """
    Raised when the file is empty or exceeds the size limit.
    """


class UnsafeFileNameError(FileValidationError):
    """
    Raised when a filename contains unsafe or invalid information.
    """


class InvalidFileSourceError(FileValidationError):
    """
    Raised when the supplied file source is invalid.
    """


@dataclass(frozen=True)
class FileMetadata:
    """
    Structured metadata for an evidence file.
    """

    original_name: str
    safe_name: str
    base_name: str
    extension: str
    category: str
    mime_type: str
    size_bytes: int
    readable_size: str
    absolute_path: str | None
    last_modified: str | None

    def to_dict(self) -> dict:
        """
        Convert metadata into a dictionary.
        """

        return asdict(self)


@dataclass(frozen=True)
class ValidationResult:
    """
    Structured file-validation result.
    """

    is_valid: bool
    message: str
    metadata: FileMetadata | None = None

    def to_dict(self) -> dict:
        """
        Convert validation result into a dictionary.
        """

        result = asdict(self)

        if self.metadata:
            result["metadata"] = self.metadata.to_dict()

        return result


def normalize_extension(
    extension: str,
) -> str:
    """
    Normalize a file extension.

    Example:
        PDF   -> .pdf
        .JPG  -> .jpg
    """

    if not isinstance(extension, str):
        return ""

    normalized = extension.strip().lower()

    if normalized and not normalized.startswith("."):
        normalized = f".{normalized}"

    return normalized


def get_file_extension(
    file_name: str,
) -> str:
    """
    Return the normalized lowercase extension of a filename.
    """

    if not file_name:
        return ""

    return normalize_extension(
        Path(file_name).suffix
    )


def get_file_name_without_extension(
    file_name: str,
) -> str:
    """
    Return a filename without its extension.
    """

    if not file_name:
        return ""

    return Path(file_name).stem


def validate_filename(
    file_name: str,
) -> str:
    """
    Validate the original evidence filename.

    Prevents:

    - Empty filenames
    - Path traversal
    - Excessively long filenames
    - Null-byte characters
    """

    if not isinstance(file_name, str):
        raise UnsafeFileNameError(
            "File name must be provided as text."
        )

    normalized_name = file_name.strip()

    if not normalized_name:
        raise UnsafeFileNameError(
            "File name cannot be empty."
        )

    if "\x00" in normalized_name:
        raise UnsafeFileNameError(
            "File name contains an invalid null-byte character."
        )

    if len(normalized_name) > MAX_FILENAME_LENGTH:
        raise UnsafeFileNameError(
            f"File name cannot exceed "
            f"{MAX_FILENAME_LENGTH} characters."
        )

    if (
        "/" in normalized_name
        or "\\" in normalized_name
        or normalized_name in {".", ".."}
    ):
        raise UnsafeFileNameError(
            "Directory paths are not allowed in file names."
        )

    return normalized_name


def create_safe_filename(
    original_name: str,
    preserve_extension: bool = True,
) -> str:
    """
    Generate a sanitized and unique filename.

    Example:
        Original:
        Crime Evidence (Final).PDF

        Result:
        crime_evidence_final_a1b2c3d4.pdf
    """

    validated_name = validate_filename(
        original_name
    )

    extension = get_file_extension(
        validated_name
    )

    base_name = get_file_name_without_extension(
        validated_name
    )

    normalized_base = unicodedata.normalize(
        "NFKD",
        base_name,
    ).encode(
        "ascii",
        "ignore",
    ).decode(
        "ascii"
    )

    normalized_base = SAFE_FILENAME_PATTERN.sub(
        "_",
        normalized_base,
    ).strip(
        "._-"
    ).lower()

    if not normalized_base:
        normalized_base = "evidence"

    unique_code = uuid.uuid4().hex[:12]

    safe_name = (
        f"{normalized_base}_{unique_code}"
    )

    if preserve_extension:
        safe_name = (
            f"{safe_name}{extension}"
        )

    return safe_name


def get_mime_type(
    file_name: str,
) -> str:
    """
    Detect a probable MIME type using the filename extension.
    """

    mime_type, _ = mimetypes.guess_type(
        file_name
    )

    return (
        mime_type
        or "application/octet-stream"
    )


def get_evidence_category(
    file_name: str,
) -> str:
    """
    Determine the evidence category from its extension.
    """

    extension = get_file_extension(
        file_name
    )

    if extension in ALLOWED_IMAGE_EXTENSIONS:
        return "IMAGE"

    if extension in ALLOWED_DOCUMENT_EXTENSIONS:
        return "DOCUMENT"

    if extension in ALLOWED_VIDEO_EXTENSIONS:
        return "VIDEO"

    if extension in ALLOWED_AUDIO_EXTENSIONS:
        return "AUDIO"

    return "OTHER"


def is_dangerous_extension(
    file_name: str,
) -> bool:
    """
    Check whether a file uses a potentially dangerous extension.
    """

    extension = get_file_extension(
        file_name
    )

    return extension in DANGEROUS_EXTENSIONS


def validate_extension(
    file_name: str,
) -> str:
    """
    Validate that the file extension is supported and permitted.

    Returns:
        Normalized extension.
    """

    validated_name = validate_filename(
        file_name
    )

    extension = get_file_extension(
        validated_name
    )

    if not extension:
        raise UnsupportedFileTypeError(
            "The uploaded file has no extension."
        )

    if (
        is_dangerous_extension(validated_name)
        and not ALLOW_EXECUTABLE_FILES
    ):
        raise UnsupportedFileTypeError(
            f"Executable or dangerous file type "
            f"is not permitted: {extension}"
        )

    normalized_supported_extensions = {
        normalize_extension(item)
        for item in SUPPORTED_EXTENSIONS
    }

    if extension not in normalized_supported_extensions:
        supported_text = ", ".join(
            sorted(
                normalized_supported_extensions
            )
        )

        raise UnsupportedFileTypeError(
            f"Unsupported file type: {extension}. "
            f"Supported types: {supported_text}"
        )

    return extension


def validate_file_size(
    file_size: int,
    maximum_size: int = MAX_FILE_SIZE,
) -> int:
    """
    Validate evidence file size.

    Returns:
        Validated file size in bytes.
    """

    if not isinstance(file_size, int):
        raise InvalidFileSizeError(
            "File size must be an integer."
        )

    if file_size <= 0:
        raise InvalidFileSizeError(
            "Empty evidence files are not allowed."
        )

    if maximum_size <= 0:
        raise ValueError(
            "Maximum file size must be greater than zero."
        )

    if file_size > maximum_size:
        raise InvalidFileSizeError(
            "Evidence file exceeds the maximum allowed size "
            f"of {human_readable_size(maximum_size)}."
        )

    return file_size


def human_readable_size(
    file_size: int,
) -> str:
    """
    Convert a byte value into a readable unit.

    Example:
        1048576 -> 1.00 MB
    """

    if not isinstance(file_size, int):
        raise TypeError(
            "File size must be an integer."
        )

    if file_size < 0:
        raise ValueError(
            "File size cannot be negative."
        )

    units = (
        "Bytes",
        "KB",
        "MB",
        "GB",
        "TB",
        "PB",
    )

    size = float(file_size)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "Bytes":
                return f"{int(size)} {unit}"

            return f"{size:.2f} {unit}"

        size /= 1024

    return f"{size:.2f} PB"


def get_uploaded_file_size(
    uploaded_file,
) -> int:
    """
    Retrieve the size of a Django uploaded file or file object.
    """

    if uploaded_file is None:
        raise InvalidFileSourceError(
            "Uploaded file cannot be None."
        )

    if hasattr(uploaded_file, "size"):
        try:
            return int(
                uploaded_file.size
            )

        except (TypeError, ValueError) as error:
            raise InvalidFileSourceError(
                "Unable to determine uploaded file size."
            ) from error

    if (
        hasattr(uploaded_file, "seek")
        and hasattr(uploaded_file, "tell")
    ):
        original_position = None

        try:
            original_position = uploaded_file.tell()

            uploaded_file.seek(
                0,
                os.SEEK_END,
            )

            file_size = uploaded_file.tell()

            return int(
                file_size
            )

        except (
            OSError,
            TypeError,
            ValueError,
        ) as error:
            raise InvalidFileSourceError(
                "Unable to determine uploaded file size."
            ) from error

        finally:
            if original_position is not None:
                try:
                    uploaded_file.seek(
                        original_position
                    )

                except (
                    OSError,
                    ValueError,
                ):
                    pass

    raise InvalidFileSourceError(
        "The supplied object is not a valid uploaded file."
    )


def validate_uploaded_file(
    uploaded_file,
    maximum_size: int = MAX_FILE_SIZE,
) -> ValidationResult:
    """
    Validate a Django uploaded evidence file.

    Checks:

    - Filename
    - Extension
    - Dangerous file types
    - File size
    - Basic MIME type
    """

    if not ENABLE_FILE_VALIDATION:
        return ValidationResult(
            is_valid=True,
            message="File validation is disabled.",
        )

    if uploaded_file is None:
        raise InvalidFileSourceError(
            "No evidence file was provided."
        )

    file_name = getattr(
        uploaded_file,
        "name",
        "",
    )

    validated_name = validate_filename(
        file_name
    )

    validate_extension(
        validated_name
    )

    file_size = get_uploaded_file_size(
        uploaded_file
    )

    validate_file_size(
        file_size=file_size,
        maximum_size=maximum_size,
    )

    metadata = FileMetadata(
        original_name=validated_name,
        safe_name=create_safe_filename(
            validated_name
        ),
        base_name=get_file_name_without_extension(
            validated_name
        ),
        extension=get_file_extension(
            validated_name
        ),
        category=get_evidence_category(
            validated_name
        ),
        mime_type=get_mime_type(
            validated_name
        ),
        size_bytes=file_size,
        readable_size=human_readable_size(
            file_size
        ),
        absolute_path=None,
        last_modified=None,
    )

    return ValidationResult(
        is_valid=True,
        message="Evidence file validation completed successfully.",
        metadata=metadata,
    )


def extract_file_metadata(
    file_path: str | Path,
) -> FileMetadata:
    """
    Extract metadata from an existing file path.
    """

    path = Path(
        file_path
    ).expanduser()

    if not path.exists():
        raise FileNotFoundError(
            f"Evidence file does not exist: {path}"
        )

    if not path.is_file():
        raise InvalidFileSourceError(
            f"Evidence source is not a file: {path}"
        )

    validated_name = validate_filename(
        path.name
    )

    validate_extension(
        validated_name
    )

    file_size = validate_file_size(
        path.stat().st_size
    )

    modified_timestamp = path.stat().st_mtime

    modified_datetime = datetime.fromtimestamp(
        modified_timestamp,
        tz=timezone.utc,
    ).isoformat()

    return FileMetadata(
        original_name=validated_name,
        safe_name=create_safe_filename(
            validated_name
        ),
        base_name=path.stem,
        extension=get_file_extension(
            validated_name
        ),
        category=get_evidence_category(
            validated_name
        ),
        mime_type=get_mime_type(
            validated_name
        ),
        size_bytes=file_size,
        readable_size=human_readable_size(
            file_size
        ),
        absolute_path=str(
            path.resolve()
        ),
        last_modified=modified_datetime,
    )


def is_image(
    file_name: str,
) -> bool:
    """
    Return True when the file is a supported image.
    """

    return (
        get_file_extension(file_name)
        in ALLOWED_IMAGE_EXTENSIONS
    )


def is_document(
    file_name: str,
) -> bool:
    """
    Return True when the file is a supported document.
    """

    return (
        get_file_extension(file_name)
        in ALLOWED_DOCUMENT_EXTENSIONS
    )


def is_audio(
    file_name: str,
) -> bool:
    """
    Return True when the file is supported audio.
    """

    return (
        get_file_extension(file_name)
        in ALLOWED_AUDIO_EXTENSIONS
    )


def is_video(
    file_name: str,
) -> bool:
    """
    Return True when the file is a supported video.
    """

    return (
        get_file_extension(file_name)
        in ALLOWED_VIDEO_EXTENSIONS
    )


def is_pdf(
    file_name: str,
) -> bool:
    """
    Return True when the file is a PDF document.
    """

    return (
        get_file_extension(file_name)
        == ".pdf"
    )