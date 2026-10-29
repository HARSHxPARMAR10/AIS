"""
AIDEX Digital Evidence Hashing Service

This module provides secure hashing and integrity verification
for digital evidence handled by the AIDEX system.

Features:
- SHA-256 hashing
- SHA-512 hashing
- File-path support
- Django uploaded-file support
- Chunk-based processing
- Constant-time hash comparison
- Structured integrity reports
- Professional exception handling
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Final, Union


FileSource = Union[str, Path, BinaryIO]

DEFAULT_ALGORITHM: Final[str] = "sha256"
DEFAULT_CHUNK_SIZE: Final[int] = 1024 * 1024


class EvidenceHashingError(Exception):
    """
    Base exception raised when evidence hashing fails.
    """


class UnsupportedHashAlgorithmError(EvidenceHashingError):
    """
    Raised when an unsupported hashing algorithm is requested.
    """


class InvalidEvidenceSourceError(EvidenceHashingError):
    """
    Raised when the supplied evidence source is invalid.
    """


@dataclass(frozen=True)
class IntegrityReport:
    """
    Represents the result of evidence integrity verification.
    """

    algorithm: str
    calculated_hash: str
    stored_hash: str | None
    integrity_verified: bool | None
    file_size: int | None

    def to_dict(self) -> dict:
        """
        Convert the report into a dictionary.
        """

        return asdict(self)


def normalize_algorithm_name(
    algorithm: str,
) -> str:
    """
    Normalize a hashing algorithm name.

    Examples:
        SHA-256 -> sha256
        sha_512 -> sha512
    """

    if not isinstance(algorithm, str):
        raise UnsupportedHashAlgorithmError(
            "Hash algorithm must be provided as a string."
        )

    normalized = (
        algorithm.strip()
        .lower()
        .replace("-", "")
        .replace("_", "")
    )

    supported_algorithms = {
        "sha256",
        "sha512",
    }

    if normalized not in supported_algorithms:
        raise UnsupportedHashAlgorithmError(
            f"Unsupported hash algorithm: {algorithm}. "
            "Supported algorithms are SHA-256 and SHA-512."
        )

    return normalized


def create_hash_object(
    algorithm: str = DEFAULT_ALGORITHM,
):
    """
    Create and return a hashlib object.
    """

    normalized_algorithm = normalize_algorithm_name(
        algorithm
    )

    try:
        return hashlib.new(
            normalized_algorithm
        )

    except ValueError as error:
        raise UnsupportedHashAlgorithmError(
            f"Hash algorithm is unavailable: {algorithm}"
        ) from error


def validate_chunk_size(
    chunk_size: int,
) -> None:
    """
    Validate the requested processing chunk size.
    """

    if not isinstance(chunk_size, int):
        raise ValueError(
            "Chunk size must be an integer."
        )

    if chunk_size <= 0:
        raise ValueError(
            "Chunk size must be greater than zero."
        )


def get_file_size(
    file_source: FileSource,
) -> int | None:
    """
    Return the file size without permanently changing
    the current file-object position.
    """

    if isinstance(file_source, (str, Path)):
        file_path = Path(file_source)

        if not file_path.exists():
            raise FileNotFoundError(
                f"Evidence file does not exist: {file_path}"
            )

        if not file_path.is_file():
            raise InvalidEvidenceSourceError(
                f"Evidence source is not a file: {file_path}"
            )

        return file_path.stat().st_size

    if hasattr(file_source, "size"):
        try:
            return int(file_source.size)

        except (TypeError, ValueError):
            return None

    if (
        hasattr(file_source, "tell")
        and hasattr(file_source, "seek")
    ):
        original_position = None

        try:
            original_position = file_source.tell()

            file_source.seek(
                0,
                2,
            )

            file_size = file_source.tell()

            return file_size

        except (OSError, ValueError):
            return None

        finally:
            if original_position is not None:
                try:
                    file_source.seek(
                        original_position
                    )

                except (OSError, ValueError):
                    pass

    return None


def hash_binary_stream(
    file_object: BinaryIO,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Generate a hash from an opened binary file object.

    The file is processed in chunks so large evidence files
    are not loaded completely into memory.
    """

    validate_chunk_size(
        chunk_size
    )

    if not hasattr(file_object, "read"):
        raise InvalidEvidenceSourceError(
            "The supplied object is not a readable file."
        )

    hash_object = create_hash_object(
        algorithm
    )

    original_position = None

    try:
        if hasattr(file_object, "tell"):
            original_position = file_object.tell()

        if hasattr(file_object, "seek"):
            file_object.seek(0)

        while True:
            chunk = file_object.read(
                chunk_size
            )

            if not chunk:
                break

            if isinstance(chunk, str):
                chunk = chunk.encode(
                    "utf-8"
                )

            if not isinstance(
                chunk,
                (bytes, bytearray),
            ):
                raise InvalidEvidenceSourceError(
                    "Evidence file must be opened in binary mode."
                )

            hash_object.update(
                chunk
            )

    except (
        OSError,
        TypeError,
        ValueError,
    ) as error:
        raise EvidenceHashingError(
            f"Unable to calculate evidence hash: {error}"
        ) from error

    finally:
        if (
            original_position is not None
            and hasattr(file_object, "seek")
        ):
            try:
                file_object.seek(
                    original_position
                )

            except (OSError, ValueError):
                pass

    return hash_object.hexdigest()


def generate_file_hash(
    file_source: FileSource,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Generate a secure hash for an evidence file.

    Args:
        file_source:
            File path, pathlib.Path object,
            Django uploaded file or binary file object.

        algorithm:
            SHA-256 or SHA-512.

        chunk_size:
            Number of bytes processed per iteration.

    Returns:
        Hexadecimal hash string.
    """

    validate_chunk_size(
        chunk_size
    )

    if isinstance(file_source, (str, Path)):
        file_path = Path(file_source)

        if not file_path.exists():
            raise FileNotFoundError(
                f"Evidence file does not exist: {file_path}"
            )

        if not file_path.is_file():
            raise InvalidEvidenceSourceError(
                f"Evidence source is not a file: {file_path}"
            )

        try:
            with file_path.open("rb") as evidence_file:
                return hash_binary_stream(
                    file_object=evidence_file,
                    algorithm=algorithm,
                    chunk_size=chunk_size,
                )

        except OSError as error:
            raise EvidenceHashingError(
                f"Unable to open evidence file: {error}"
            ) from error

    return hash_binary_stream(
        file_object=file_source,
        algorithm=algorithm,
        chunk_size=chunk_size,
    )


def generate_sha256(
    file_source: FileSource,
) -> str:
    """
    Generate a SHA-256 hash for digital evidence.
    """

    return generate_file_hash(
        file_source=file_source,
        algorithm="sha256",
    )


def generate_sha512(
    file_source: FileSource,
) -> str:
    """
    Generate a SHA-512 hash for digital evidence.
    """

    return generate_file_hash(
        file_source=file_source,
        algorithm="sha512",
    )


def compare_hashes(
    first_hash: str,
    second_hash: str,
) -> bool:
    """
    Compare two hashes using constant-time comparison.
    """

    if not isinstance(first_hash, str):
        return False

    if not isinstance(second_hash, str):
        return False

    normalized_first = (
        first_hash.strip().lower()
    )

    normalized_second = (
        second_hash.strip().lower()
    )

    if not normalized_first:
        return False

    if not normalized_second:
        return False

    return hmac.compare_digest(
        normalized_first,
        normalized_second,
    )


def verify_file_integrity(
    file_source: FileSource,
    expected_hash: str,
    algorithm: str = DEFAULT_ALGORITHM,
) -> bool:
    """
    Verify whether evidence still matches its stored hash.
    """

    if not expected_hash:
        return False

    calculated_hash = generate_file_hash(
        file_source=file_source,
        algorithm=algorithm,
    )

    return compare_hashes(
        calculated_hash,
        expected_hash,
    )


def create_integrity_report(
    file_source: FileSource,
    stored_hash: str | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
) -> IntegrityReport:
    """
    Create a structured integrity verification report.
    """

    normalized_algorithm = normalize_algorithm_name(
        algorithm
    )

    calculated_hash = generate_file_hash(
        file_source=file_source,
        algorithm=normalized_algorithm,
    )

    integrity_verified = None

    if stored_hash:
        integrity_verified = compare_hashes(
            calculated_hash,
            stored_hash,
        )

    readable_algorithm = {
        "sha256": "SHA-256",
        "sha512": "SHA-512",
    }[normalized_algorithm]

    return IntegrityReport(
        algorithm=readable_algorithm,
        calculated_hash=calculated_hash,
        stored_hash=stored_hash,
        integrity_verified=integrity_verified,
        file_size=get_file_size(
            file_source
        ),
    )


def verify_evidence_record(
    evidence,
    algorithm: str = DEFAULT_ALGORITHM,
) -> IntegrityReport:
    """
    Verify a Django Evidence model instance.

    Expected fields:
    - evidence_file
    - sha256_hash
    """

    if evidence is None:
        raise InvalidEvidenceSourceError(
            "Evidence record cannot be None."
        )

    if not hasattr(
        evidence,
        "evidence_file",
    ):
        raise InvalidEvidenceSourceError(
            "Evidence record has no evidence_file field."
        )

    if not evidence.evidence_file:
        raise InvalidEvidenceSourceError(
            "Evidence record does not contain a file."
        )

    stored_hash = getattr(
        evidence,
        "sha256_hash",
        None,
    )

    file_object = evidence.evidence_file

    try:
        file_object.open("rb")

        return create_integrity_report(
            file_source=file_object,
            stored_hash=stored_hash,
            algorithm=algorithm,
        )

    except OSError as error:
        raise EvidenceHashingError(
            f"Unable to access evidence file: {error}"
        ) from error

    finally:
        try:
            file_object.close()

        except Exception:
            pass