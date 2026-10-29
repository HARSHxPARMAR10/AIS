"""
AIDEX Reports Models

Professional investigation-report data model for:

- Case-linked investigation reports
- Evidence and AI-analysis traceability
- Controlled review / approval / publication workflow
- Report versioning
- Secure file metadata and SHA-256 integrity
- Archive / restore support
- Immutable-style report audit events

Important:
    Run migrations after replacing this file:

        python manage.py makemigrations reports
        python manage.py migrate
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator, MinValueValidator
from django.db import models
from django.db.models import Q
from django.utils import timezone

from cases.models import Case


MAX_REPORT_FILE_SIZE = 25 * 1024 * 1024

ALLOWED_REPORT_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
}

EXECUTABLE_REPORT_SIGNATURES = (
    b"MZ",  # Windows PE/DOS executable
    b"\x7fELF",  # Linux executable
    b"\xca\xfe\xba\xbe",  # Java class / Mach-O universal binary
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)

OLE_COMPOUND_FILE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

ZIP_FILE_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
)


def normalize_text(value: Any) -> str:
    """
    Normalize user-entered report text without destroying paragraph breaks.
    """

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


def safe_report_directory_component(
    value: Any,
) -> str:
    """
    Convert a case number into a safe storage-directory component.
    """

    cleaned = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        str(value or "").strip(),
    ).strip("._-")

    return cleaned[:100] or "case"


def report_upload_path(
    instance: "Report",
    filename: str,
) -> str:
    """
    Store report files under a case-specific directory using a UUID filename.

    Example:
        reports/AIDEX-20260804-ABCD1234/report_<uuid>.pdf
    """

    extension = (
        Path(
            os.path.basename(
                filename
            )
        )
        .suffix
        .lower()
    )

    case_number = safe_report_directory_component(
        getattr(
            instance.case,
            "case_number",
            "case",
        )
    )

    secure_name = (
        f"report_{uuid.uuid4().hex}"
        f"{extension}"
    )

    return (
        f"reports/"
        f"{case_number}/"
        f"{secure_name}"
    )


def calculate_uploaded_file_sha256(
    file_object: Any,
) -> str:
    """
    Calculate SHA-256 for an uploaded/stored file while restoring its pointer.

    Report files are capped at 25 MB, so hashing synchronously is acceptable
    for this project and gives each generated/uploaded file an integrity
    fingerprint.
    """

    sha256 = hashlib.sha256()

    original_position: int | None = None

    try:
        if hasattr(
            file_object,
            "tell",
        ):
            original_position = file_object.tell()
    except (
        OSError,
        ValueError,
    ):
        original_position = None

    try:
        if hasattr(
            file_object,
            "seek",
        ):
            file_object.seek(0)

        chunks = getattr(
            file_object,
            "chunks",
            None,
        )

        if callable(chunks):
            for chunk in chunks():
                sha256.update(
                    chunk
                )
        else:
            while True:
                chunk = file_object.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                sha256.update(
                    chunk
                )

    except (
        OSError,
        ValueError,
        AttributeError,
    ) as exc:
        raise ValidationError({
            "report_file": (
                "The report file could not be read for "
                "integrity hashing."
            ),
        }) from exc

    finally:
        if (
            original_position is not None
            and hasattr(
                file_object,
                "seek",
            )
        ):
            try:
                file_object.seek(
                    original_position
                )
            except (
                OSError,
                ValueError,
            ):
                pass

    return sha256.hexdigest()


def validate_report_file_signature(
    file_object: Any,
) -> None:
    """
    Verify that an uploaded report's bytes match its claimed extension.

    Browser MIME types and filenames are controlled by the uploader. This
    lightweight signature check prevents an executable or unrelated binary
    from being stored merely by renaming it to PDF, DOC or DOCX.
    """

    original_name = os.path.basename(
        str(
            getattr(
                file_object,
                "name",
                "",
            )
            or ""
        )
    )

    extension = (
        Path(original_name)
        .suffix
        .lower()
        .lstrip(".")
    )

    if extension not in ALLOWED_REPORT_EXTENSIONS:
        raise ValidationError(
            "Unsupported report file format."
        )

    original_position: int | None = None

    try:
        if hasattr(file_object, "tell"):
            original_position = file_object.tell()
    except (
        OSError,
        ValueError,
    ):
        original_position = None

    try:
        file_object.seek(0)
        header = file_object.read(1024)
    except (
        AttributeError,
        OSError,
        ValueError,
    ) as exc:
        raise ValidationError(
            "The report file could not be inspected safely."
        ) from exc
    finally:
        try:
            file_object.seek(
                original_position or 0
            )
        except (
            AttributeError,
            OSError,
            ValueError,
        ):
            pass

    if not header:
        raise ValidationError(
            "Empty report files are not allowed."
        )

    if header.startswith(
        EXECUTABLE_REPORT_SIGNATURES
    ):
        raise ValidationError(
            "Executable files are not allowed as report uploads."
        )

    signature_matches = False

    if extension == "pdf":
        # ISO 32000 permits the PDF header within the first 1024 bytes.
        signature_matches = b"%PDF-" in header

    elif extension == "doc":
        signature_matches = header.startswith(
            OLE_COMPOUND_FILE_SIGNATURE
        )

    elif extension == "docx":
        signature_matches = header.startswith(
            ZIP_FILE_SIGNATURES
        )

    if not signature_matches:
        raise ValidationError(
            "The report file content does not match its filename extension."
        )


class Report(models.Model):
    """
    Professional AIDEX investigation report.

    ``role`` permissions are handled in forms/views/services. This model
    protects core report-state consistency regardless of which UI saves it.
    """

    class ReportType(models.TextChoices):
        PRELIMINARY = (
            "PRELIMINARY",
            "Preliminary Report",
        )
        EVIDENCE = (
            "EVIDENCE",
            "Evidence Report",
        )
        AI_ANALYSIS = (
            "AI_ANALYSIS",
            "AI Analysis Report",
        )
        TECHNICAL = (
            "TECHNICAL",
            "Technical Report",
        )
        INVESTIGATION = (
            "INVESTIGATION",
            "Investigation Report",
        )
        FINAL = (
            "FINAL",
            "Final Investigation Report",
        )
        COURT_SUBMISSION = (
            "COURT_SUBMISSION",
            "Court Submission Report",
        )

    class Status(models.TextChoices):
        DRAFT = (
            "DRAFT",
            "Draft",
        )
        UNDER_REVIEW = (
            "UNDER_REVIEW",
            "Under Review",
        )
        APPROVED = (
            "APPROVED",
            "Approved",
        )
        REJECTED = (
            "REJECTED",
            "Rejected",
        )
        PUBLISHED = (
            "PUBLISHED",
            "Published",
        )
        ARCHIVED = (
            "ARCHIVED",
            "Archived",
        )

    STATUS_TRANSITIONS = {
        Status.DRAFT: (
            Status.UNDER_REVIEW,
            Status.ARCHIVED,
        ),
        Status.UNDER_REVIEW: (
            Status.DRAFT,
            Status.APPROVED,
            Status.REJECTED,
            Status.ARCHIVED,
        ),
        Status.REJECTED: (
            Status.DRAFT,
            Status.UNDER_REVIEW,
            Status.ARCHIVED,
        ),
        Status.APPROVED: (
            Status.UNDER_REVIEW,
            Status.PUBLISHED,
            Status.ARCHIVED,
        ),
        Status.PUBLISHED: (
            Status.ARCHIVED,
        ),
        Status.ARCHIVED: (),
    }

    FINAL_REVIEW_STATUSES = {
        Status.APPROVED,
        Status.PUBLISHED,
    }

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="Report ID",
    )

    report_number = models.CharField(
        max_length=50,
        unique=True,
        editable=False,
        db_index=True,
        verbose_name="Report Number",
    )

    case = models.ForeignKey(
        Case,
        on_delete=models.PROTECT,
        related_name="investigation_reports",
        verbose_name="Related Case",
        help_text=(
            "Cyber-crime case associated with this report."
        ),
    )

    report_title = models.CharField(
        max_length=200,
        verbose_name="Report Title",
        help_text=(
            "Enter a clear and descriptive report title."
        ),
    )

    report_type = models.CharField(
        max_length=30,
        choices=ReportType.choices,
        default=ReportType.INVESTIGATION,
        db_index=True,
        verbose_name="Report Type",
    )

    version = models.PositiveIntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
        ],
        verbose_name="Report Version",
        help_text=(
            "Version number for this report lineage."
        ),
    )

    supersedes = models.ForeignKey(
        "self",
        on_delete=models.PROTECT,
        related_name="revisions",
        null=True,
        blank=True,
        verbose_name="Supersedes Report",
        help_text=(
            "Previous report version replaced by this revision."
        ),
    )

    summary = models.TextField(
        blank=True,
        verbose_name="Executive Summary",
        help_text=(
            "Concise overview of the investigation and report scope."
        ),
    )

    findings = models.TextField(
        blank=True,
        verbose_name="Investigation Findings",
        help_text=(
            "Material findings supported by the investigation record."
        ),
    )

    evidence_summary = models.TextField(
        blank=True,
        verbose_name="Evidence Summary",
        help_text=(
            "Evidence considered while preparing this report."
        ),
    )

    ai_analysis_summary = models.TextField(
        blank=True,
        verbose_name="AI Analysis Summary",
        help_text=(
            "Human-reviewed summary of relevant AI-assisted analysis."
        ),
    )

    conclusion = models.TextField(
        blank=True,
        verbose_name="Conclusion",
        help_text=(
            "Evidence-grounded investigation conclusion."
        ),
    )

    recommendations = models.TextField(
        blank=True,
        verbose_name="Recommendations",
        help_text=(
            "Recommended investigative, technical or procedural next steps."
        ),
    )

    review_notes = models.TextField(
        blank=True,
        verbose_name="Review Notes",
        help_text=(
            "Reviewer observations, requested corrections and limitations."
        ),
    )

    approval_notes = models.TextField(
        blank=True,
        verbose_name="Approval Notes",
        help_text=(
            "Approval observations or conditions."
        ),
    )

    rejection_reason = models.TextField(
        blank=True,
        verbose_name="Rejection Reason",
        help_text=(
            "Required when a report is rejected."
        ),
    )

    report_file = models.FileField(
        upload_to=report_upload_path,
        validators=[
            FileExtensionValidator(
                allowed_extensions=sorted(
                    ALLOWED_REPORT_EXTENSIONS
                )
            ),
        ],
        blank=True,
        null=True,
        verbose_name="Generated Report File",
    )

    original_filename = models.CharField(
        max_length=255,
        blank=True,
        editable=False,
        verbose_name="Original File Name",
    )

    file_size = models.PositiveBigIntegerField(
        default=0,
        editable=False,
        verbose_name="File Size in Bytes",
    )

    file_sha256 = models.CharField(
        max_length=64,
        blank=True,
        editable=False,
        db_index=True,
        verbose_name="Report File SHA-256",
    )

    included_evidence = models.ManyToManyField(
        "evidence.Evidence",
        related_name="included_in_reports",
        blank=True,
        verbose_name="Included Evidence",
        help_text=(
            "Evidence records explicitly referenced by this report."
        ),
    )

    included_analyses = models.ManyToManyField(
        "ai_engine.AIAnalysis",
        related_name="included_in_reports",
        blank=True,
        verbose_name="Included AI Analyses",
        help_text=(
            "AI analyses explicitly referenced by this report."
        ),
    )

    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="generated_investigation_reports",
        verbose_name="Generated By",
    )

    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="reviewed_investigation_reports",
        null=True,
        blank=True,
        verbose_name="Reviewed By",
    )

    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="approved_investigation_reports",
        null=True,
        blank=True,
        verbose_name="Approved By",
    )

    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="published_investigation_reports",
        null=True,
        blank=True,
        verbose_name="Published By",
    )

    archived_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="archived_investigation_reports",
        null=True,
        blank=True,
        verbose_name="Archived By",
    )

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT,
        db_index=True,
        verbose_name="Report Status",
    )

    pre_archive_status = models.CharField(
        max_length=20,
        choices=Status.choices,
        blank=True,
        editable=False,
        verbose_name="Pre-Archive Status",
    )

    generated_date = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name="Generated Date",
    )

    reviewed_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Reviewed Date",
    )

    approved_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Approved Date",
    )

    published_date = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Published Date",
    )

    archived_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Archived At",
    )

    updated_date = models.DateTimeField(
        auto_now=True,
        db_index=True,
        verbose_name="Updated Date",
    )

    archive_reason = models.TextField(
        blank=True,
        verbose_name="Archive Reason",
    )

    is_confidential = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name="Confidential Report",
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name="Active Report",
    )

    class Meta:
        db_table = (
            "aidex_investigation_reports"
        )

        ordering = (
            "-generated_date",
        )

        get_latest_by = (
            "generated_date"
        )

        verbose_name = (
            "Investigation Report"
        )

        verbose_name_plural = (
            "Investigation Reports"
        )

        indexes = [
            models.Index(
                fields=[
                    "case",
                    "status",
                ],
                name="report_case_status_idx",
            ),
            models.Index(
                fields=[
                    "report_type",
                    "status",
                ],
                name="report_type_status_idx",
            ),
            models.Index(
                fields=[
                    "generated_by",
                    "generated_date",
                ],
                name="report_author_date_idx",
            ),
            models.Index(
                fields=[
                    "is_confidential",
                    "is_active",
                ],
                name="report_security_idx",
            ),
            models.Index(
                fields=[
                    "case",
                    "report_type",
                    "version",
                ],
                name="report_version_lookup_idx",
            ),
        ]

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "case",
                    "report_title",
                    "report_type",
                    "version",
                ],
                name="unique_case_report_version",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        status="ARCHIVED",
                        is_active=False,
                    )
                    | (
                        ~Q(
                            status="ARCHIVED"
                        )
                        & Q(
                            is_active=True
                        )
                    )
                ),
                name="report_archive_active_consistency",
            ),
            models.CheckConstraint(
                condition=(
                    ~Q(
                        status="ARCHIVED"
                    )
                    | Q(
                        archived_at__isnull=False
                    )
                ),
                name="report_archived_requires_timestamp",
            ),
        ]

        permissions = [
            (
                "review_report",
                "Can review investigation report",
            ),
            (
                "approve_report",
                "Can approve investigation report",
            ),
            (
                "reject_report",
                "Can reject investigation report",
            ),
            (
                "publish_report",
                "Can publish investigation report",
            ),
            (
                "download_report",
                "Can download investigation report",
            ),
            (
                "archive_report",
                "Can archive investigation report",
            ),
            (
                "restore_report",
                "Can restore archived investigation report",
            ),
            (
                "create_report_revision",
                "Can create a new investigation report revision",
            ),
            (
                "view_confidential_report",
                "Can view confidential investigation report",
            ),
            (
                "view_report_audit",
                "Can view investigation report audit history",
            ),
        ]

    def generate_report_number(
        self,
    ) -> str:
        """
        Generate a human-readable unique report identifier.

        Example:
            RPT-20260810-A1B2C3D4
        """

        current_date = timezone.localdate().strftime(
            "%Y%m%d"
        )

        unique_code = (
            uuid.uuid4()
            .hex[:8]
            .upper()
        )

        return (
            f"RPT-"
            f"{current_date}-"
            f"{unique_code}"
        )

    def get_allowed_next_statuses(
        self,
    ) -> tuple[str, ...]:
        """
        Return status transitions available through the normal workflow.
        """

        if self.status == self.Status.ARCHIVED:
            return ()

        return tuple(
            self.STATUS_TRANSITIONS.get(
                self.status,
                (),
            )
        )

    def can_transition_to(
        self,
        target_status: str,
    ) -> bool:
        """
        Return whether target_status is a valid normal transition.
        """

        if target_status == self.status:
            return True

        return target_status in (
            self.get_allowed_next_statuses()
        )

    @property
    def restore_status(
        self,
    ) -> str:
        """
        Return the safe status used by the dedicated restore workflow.
        """

        if (
            self.pre_archive_status
            and self.pre_archive_status
            != self.Status.ARCHIVED
        ):
            return self.pre_archive_status

        return self.Status.DRAFT

    def _get_persisted_state(
        self,
    ) -> dict[str, Any] | None:
        """
        Return status/lifecycle values currently stored in the database.
        """

        if self._state.adding or not self.pk:
            return None

        return (
            type(self)
            .objects
            .filter(
                pk=self.pk
            )
            .values(
                "status",
                "pre_archive_status",
                "is_active",
            )
            .first()
        )

    def _validate_status_transition(
        self,
        persisted_state: dict[str, Any] | None,
    ) -> None:
        """
        Block arbitrary report-state jumps at model level.

        Archive restore is the only special transition: an archived report may
        return to the status captured in pre_archive_status.
        """

        if persisted_state is None:
            return

        old_status = persisted_state[
            "status"
        ]

        if old_status == self.status:
            return

        if old_status == self.Status.ARCHIVED:
            safe_restore_status = (
                persisted_state.get(
                    "pre_archive_status"
                )
                or self.Status.DRAFT
            )

            if self.status == safe_restore_status:
                return

            raise ValidationError({
                "status": (
                    "Archived reports can only be restored through "
                    "their recorded pre-archive status."
                ),
            })

        allowed_statuses = (
            self.STATUS_TRANSITIONS.get(
                old_status,
                (),
            )
        )

        if self.status not in allowed_statuses:
            old_label = dict(
                self.Status.choices
            ).get(
                old_status,
                old_status,
            )

            new_label = dict(
                self.Status.choices
            ).get(
                self.status,
                self.status,
            )

            raise ValidationError({
                "status": (
                    "Invalid report status transition: "
                    f"{old_label} -> {new_label}."
                ),
            })

    def _prepare_file_metadata(
        self,
    ) -> set[str]:
        """
        Capture original upload metadata only for a new/replacement file.

        FieldFile.name becomes the generated storage path after persistence.
        Checking _committed prevents that UUID storage name from overwriting
        original_filename on later metadata-only saves.
        """

        changed_fields: set[str] = set()

        report_file = self.report_file

        if not report_file:
            if self.original_filename:
                self.original_filename = ""
                changed_fields.add(
                    "original_filename"
                )

            if self.file_size:
                self.file_size = 0
                changed_fields.add(
                    "file_size"
                )

            if self.file_sha256:
                self.file_sha256 = ""
                changed_fields.add(
                    "file_sha256"
                )

            return changed_fields

        is_new_or_replacement = not getattr(
            report_file,
            "_committed",
            True,
        )

        if not is_new_or_replacement:
            return changed_fields

        original_name = os.path.basename(
            str(
                report_file.name
                or ""
            )
        )

        extension = (
            Path(
                original_name
            )
            .suffix
            .lower()
            .lstrip(".")
        )

        if (
            extension
            not in ALLOWED_REPORT_EXTENSIONS
        ):
            raise ValidationError({
                "report_file": (
                    "Unsupported report file format."
                ),
            })

        try:
            size = int(
                report_file.size
            )
        except (
            TypeError,
            ValueError,
            OSError,
        ) as exc:
            raise ValidationError({
                "report_file": (
                    "The report file size could not be determined."
                ),
            }) from exc

        if size <= 0:
            raise ValidationError({
                "report_file": (
                    "Empty report files are not allowed."
                ),
            })

        if size > MAX_REPORT_FILE_SIZE:
            raise ValidationError({
                "report_file": (
                    "Report file size cannot exceed 25 MB."
                ),
            })

        if len(original_name) > 255:
            raise ValidationError({
                "report_file": (
                    "Report filename cannot exceed 255 characters."
                ),
            })

        try:
            validate_report_file_signature(
                report_file
            )
        except ValidationError as exc:
            raise ValidationError({
                "report_file": exc.messages,
            }) from exc

        self.original_filename = original_name
        self.file_size = size
        self.file_sha256 = (
            calculate_uploaded_file_sha256(
                report_file
            )
        )

        changed_fields.update({
            "original_filename",
            "file_size",
            "file_sha256",
        })

        return changed_fields

    def clean(
        self,
    ) -> None:
        """
        Validate report content, review state and publication state.
        """

        super().clean()

        self.report_title = normalize_text(
            self.report_title
        )

        if len(
            self.report_title
        ) < 5:
            raise ValidationError({
                "report_title": (
                    "Report title must contain at least 5 characters."
                ),
            })

        for field_name in (
            "summary",
            "findings",
            "evidence_summary",
            "ai_analysis_summary",
            "conclusion",
            "recommendations",
            "review_notes",
            "approval_notes",
            "rejection_reason",
            "archive_reason",
        ):
            setattr(
                self,
                field_name,
                normalize_text(
                    getattr(
                        self,
                        field_name,
                        "",
                    )
                ),
            )

        if (
            self.supersedes_id
            and self.supersedes_id == self.pk
        ):
            raise ValidationError({
                "supersedes": (
                    "A report cannot supersede itself."
                ),
            })

        if self.supersedes:
            if (
                self.supersedes.case_id
                != self.case_id
            ):
                raise ValidationError({
                    "supersedes": (
                        "A report revision must belong to the same case."
                    ),
                })

            if (
                self.supersedes.report_type
                != self.report_type
            ):
                raise ValidationError({
                    "supersedes": (
                        "A report revision must keep the same report type."
                    ),
                })

            if self.version <= self.supersedes.version:
                raise ValidationError({
                    "version": (
                        "A revision version must be greater than "
                        "the report it supersedes."
                    ),
                })

        if self.approved_by and not self.reviewed_by:
            raise ValidationError({
                "approved_by": (
                    "A report must be reviewed before approval."
                ),
            })

        if self.published_by and not self.approved_by:
            raise ValidationError({
                "published_by": (
                    "A report must be approved before publication."
                ),
            })

        if (
            self.status
            == self.Status.REJECTED
        ):
            if not self.reviewed_by:
                raise ValidationError({
                    "reviewed_by": (
                        "Rejected reports must include the reviewing user."
                    ),
                })

            if len(
                self.rejection_reason
            ) < 10:
                raise ValidationError({
                    "rejection_reason": (
                        "Provide a meaningful rejection reason of at least "
                        "10 characters."
                    ),
                })

        if (
            self.status
            in self.FINAL_REVIEW_STATUSES
        ):
            required_content = {
                "summary": self.summary,
                "findings": self.findings,
                "conclusion": self.conclusion,
            }

            for field_name, value in (
                required_content.items()
            ):
                if len(
                    normalize_text(
                        value
                    )
                ) < 10:
                    raise ValidationError({
                        field_name: (
                            "Approved/published reports require meaningful "
                            "content in this section."
                        ),
                    })

            if not self.reviewed_by:
                raise ValidationError({
                    "reviewed_by": (
                        "Approved reports must include a reviewer."
                    ),
                })

            if not self.reviewed_date:
                raise ValidationError({
                    "reviewed_date": (
                        "Approved reports must include a review timestamp."
                    ),
                })

            if not self.approved_by:
                raise ValidationError({
                    "approved_by": (
                        "Approved reports must include the approving user."
                    ),
                })

            if not self.approved_date:
                raise ValidationError({
                    "approved_date": (
                        "Approved reports must include an approval timestamp."
                    ),
                })

        if (
            self.status
            == self.Status.PUBLISHED
        ):
            if not self.published_by:
                raise ValidationError({
                    "published_by": (
                        "Published reports must include the publishing user."
                    ),
                })

            if not self.published_date:
                raise ValidationError({
                    "published_date": (
                        "Published reports must include a publication timestamp."
                    ),
                })

            if not self.report_file:
                raise ValidationError({
                    "report_file": (
                        "A published report must have a generated report file."
                    ),
                })

            extension = (
                Path(
                    self.original_filename
                    or self.report_file.name
                )
                .suffix
                .lower()
                .lstrip(".")
            )

            if extension != "pdf":
                raise ValidationError({
                    "report_file": (
                        "Published reports must use PDF format."
                    ),
                })

        if (
            self.status
            == self.Status.ARCHIVED
        ):
            if self.is_active:
                raise ValidationError({
                    "is_active": (
                        "Archived reports must be inactive."
                    ),
                })

            if (
                not self.pre_archive_status
                or self.pre_archive_status
                == self.Status.ARCHIVED
            ):
                raise ValidationError({
                    "pre_archive_status": (
                        "Archived reports must preserve their previous status."
                    ),
                })

            if len(
                self.archive_reason
            ) < 10:
                raise ValidationError({
                    "archive_reason": (
                        "Provide a meaningful archive reason of at least "
                        "10 characters."
                    ),
                })

            if not self.archived_by:
                raise ValidationError({
                    "archived_by": (
                        "Archived reports must record the archiving user."
                    ),
                })

            if not self.archived_at:
                raise ValidationError({
                    "archived_at": (
                        "Archived reports must record an archive timestamp."
                    ),
                })

        elif not self.is_active:
            raise ValidationError({
                "is_active": (
                    "Non-archived reports must remain active. "
                    "Use the dedicated archive workflow."
                ),
            })

        if (
            self.pre_archive_status
            == self.Status.ARCHIVED
        ):
            raise ValidationError({
                "pre_archive_status": (
                    "Pre-archive status cannot itself be Archived."
                ),
            })

    def save(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Save while preserving report number, lifecycle and file metadata.

        Status-transition validation is applied even when a caller bypasses
        a normal ModelForm.
        """

        if not self.report_number:
            self.report_number = (
                self.generate_report_number()
            )

        persisted_state = (
            self._get_persisted_state()
        )

        self._validate_status_transition(
            persisted_state
        )

        changed_fields: set[str] = {
            "report_number",
        }

        for field_name in (
            "report_title",
            "summary",
            "findings",
            "evidence_summary",
            "ai_analysis_summary",
            "conclusion",
            "recommendations",
            "review_notes",
            "approval_notes",
            "rejection_reason",
            "archive_reason",
        ):
            old_value = getattr(
                self,
                field_name,
                "",
            )

            new_value = normalize_text(
                old_value
            )

            if new_value != old_value:
                setattr(
                    self,
                    field_name,
                    new_value,
                )

                changed_fields.add(
                    field_name
                )

        changed_fields.update(
            self._prepare_file_metadata()
        )

        now = timezone.now()

        if (
            self.reviewed_by
            and not self.reviewed_date
        ):
            self.reviewed_date = now
            changed_fields.add(
                "reviewed_date"
            )

        if (
            self.status
            in {
                self.Status.APPROVED,
                self.Status.PUBLISHED,
            }
            and self.approved_by
            and not self.approved_date
        ):
            self.approved_date = now
            changed_fields.add(
                "approved_date"
            )

        if (
            self.status
            == self.Status.PUBLISHED
            and self.published_by
            and not self.published_date
        ):
            self.published_date = now
            changed_fields.add(
                "published_date"
            )

        if (
            persisted_state is not None
            and persisted_state[
                "status"
            ]
            != self.Status.ARCHIVED
            and self.status
            == self.Status.ARCHIVED
        ):
            self.pre_archive_status = (
                persisted_state[
                    "status"
                ]
            )
            self.is_active = False

            changed_fields.update({
                "pre_archive_status",
                "is_active",
            })

            if (
                self.archived_by
                and not self.archived_at
            ):
                self.archived_at = now
                changed_fields.add(
                    "archived_at"
                )

        elif (
            persisted_state is not None
            and persisted_state[
                "status"
            ]
            == self.Status.ARCHIVED
            and self.status
            != self.Status.ARCHIVED
        ):
            self.is_active = True
            changed_fields.add(
                "is_active"
            )

        self.full_clean()

        update_fields = kwargs.get(
            "update_fields"
        )

        if update_fields is not None:
            kwargs[
                "update_fields"
            ] = set(
                update_fields
            ) | changed_fields

        super().save(
            *args,
            **kwargs,
        )

    def __str__(
        self,
    ) -> str:
        return (
            f"{self.report_number} | "
            f"{self.report_title} "
            f"(v{self.version})"
        )

    @property
    def file_size_mb(
        self,
    ) -> float:
        return round(
            self.file_size
            / (1024 * 1024),
            2,
        )

    @property
    def has_file(
        self,
    ) -> bool:
        return bool(
            self.report_file
        )

    @property
    def is_approved(
        self,
    ) -> bool:
        return self.status in {
            self.Status.APPROVED,
            self.Status.PUBLISHED,
        }

    @property
    def is_published(
        self,
    ) -> bool:
        return (
            self.status
            == self.Status.PUBLISHED
        )

    @property
    def is_archived(
        self,
    ) -> bool:
        return (
            self.status
            == self.Status.ARCHIVED
        )

    @property
    def is_final_report(
        self,
    ) -> bool:
        return self.report_type in {
            self.ReportType.FINAL,
            self.ReportType.COURT_SUBMISSION,
        }

    @property
    def can_be_published(
        self,
    ) -> bool:
        return (
            self.status
            == self.Status.APPROVED
            and self.approved_by is not None
            and self.approved_date is not None
            and self.is_active
        )

    @property
    def can_be_edited(
        self,
    ) -> bool:
        """
        Published/archived reports are treated as immutable report versions.
        """

        return (
            self.is_active
            and self.status
            in {
                self.Status.DRAFT,
                self.Status.REJECTED,
            }
        )


class ReportAuditLog(models.Model):
    """
    Append-only-style report lifecycle event.

    Views/services should create new rows for workflow actions rather than
    editing historical rows.
    """

    class EventType(models.TextChoices):
        CREATED = (
            "CREATED",
            "Created",
        )
        UPDATED = (
            "UPDATED",
            "Updated",
        )
        FILE_GENERATED = (
            "FILE_GENERATED",
            "File Generated",
        )
        SUBMITTED = (
            "SUBMITTED",
            "Submitted for Review",
        )
        REVIEWED = (
            "REVIEWED",
            "Reviewed",
        )
        APPROVED = (
            "APPROVED",
            "Approved",
        )
        REJECTED = (
            "REJECTED",
            "Rejected",
        )
        PUBLISHED = (
            "PUBLISHED",
            "Published",
        )
        REVISION_CREATED = (
            "REVISION_CREATED",
            "Revision Created",
        )
        DOWNLOADED = (
            "DOWNLOADED",
            "Downloaded",
        )
        ARCHIVED = (
            "ARCHIVED",
            "Archived",
        )
        RESTORED = (
            "RESTORED",
            "Restored",
        )

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    report = models.ForeignKey(
        Report,
        on_delete=models.CASCADE,
        related_name="audit_logs",
    )

    event_type = models.CharField(
        max_length=30,
        choices=EventType.choices,
        db_index=True,
    )

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="report_audit_events",
        null=True,
        blank=True,
    )

    message = models.TextField(
        blank=True,
    )

    from_status = models.CharField(
        max_length=20,
        choices=Report.Status.choices,
        blank=True,
    )

    to_status = models.CharField(
        max_length=20,
        choices=Report.Status.choices,
        blank=True,
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        db_table = (
            "aidex_report_audit_logs"
        )

        ordering = (
            "-created_at",
        )

        verbose_name = (
            "Report Audit Log"
        )

        verbose_name_plural = (
            "Report Audit Logs"
        )

        indexes = [
            models.Index(
                fields=[
                    "report",
                    "created_at",
                ],
                name="report_audit_time_idx",
            ),
            models.Index(
                fields=[
                    "event_type",
                    "created_at",
                ],
                name="report_audit_event_idx",
            ),
        ]

        permissions = [
            (
                "export_report_audit",
                "Can export investigation report audit history",
            ),
        ]

    def save(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Prevent accidental editing of an existing audit event.
        """

        if self.pk:
            existing = (
                type(self)
                .objects
                .filter(
                    pk=self.pk
                )
                .exists()
            )

            if existing:
                raise ValidationError(
                    (
                        "Report audit events are immutable. "
                        "Create a new audit event instead."
                    )
                )

        self.message = normalize_text(
            self.message
        )

        super().save(
            *args,
            **kwargs,
        )

    def __str__(
        self,
    ) -> str:
        return (
            f"{self.report.report_number} | "
            f"{self.get_event_type_display()} | "
            f"{self.created_at:%Y-%m-%d %H:%M:%S}"
        )
