import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


def generate_case_number():
    """
    Generate a unique, readable case number.

    Example:
        AIDEX-20260804-8F3A91BC
    """
    current_date = timezone.now().strftime("%Y%m%d")
    unique_code = uuid.uuid4().hex[:8].upper()

    return f"AIDEX-{current_date}-{unique_code}"


class Case(models.Model):
    """
    Stores cyber-crime case information and manages the relationship
    between the case creator and assigned investigator.

    Archived cases are never permanently deleted. The model preserves the
    status that existed immediately before archival so a later restore can
    return the case to its previous investigation state.
    """

    class CrimeCategory(models.TextChoices):
        FINANCIAL_FRAUD = (
            "FINANCIAL_FRAUD",
            "Financial Fraud",
        )
        IDENTITY_THEFT = (
            "IDENTITY_THEFT",
            "Identity Theft",
        )
        CYBER_BULLYING = (
            "CYBER_BULLYING",
            "Cyber Bullying",
        )
        SOCIAL_MEDIA_CRIME = (
            "SOCIAL_MEDIA_CRIME",
            "Social Media Crime",
        )
        EMAIL_FRAUD = (
            "EMAIL_FRAUD",
            "Email Fraud",
        )
        PHISHING = (
            "PHISHING",
            "Phishing",
        )
        MALWARE_ATTACK = (
            "MALWARE_ATTACK",
            "Malware Attack",
        )
        RANSOMWARE_ATTACK = (
            "RANSOMWARE_ATTACK",
            "Ransomware Attack",
        )
        NETWORK_INTRUSION = (
            "NETWORK_INTRUSION",
            "Network Intrusion",
        )
        DATA_BREACH = (
            "DATA_BREACH",
            "Data Breach",
        )
        IDENTITY_FRAUD = (
            "IDENTITY_FRAUD",
            "Identity Fraud",
        )
        DIGITAL_FORGERY = (
            "DIGITAL_FORGERY",
            "Digital Forgery",
        )
        ONLINE_HARASSMENT = (
            "ONLINE_HARASSMENT",
            "Online Harassment",
        )
        OTHER = (
            "OTHER",
            "Other",
        )

    class Priority(models.TextChoices):
        LOW = (
            "LOW",
            "Low",
        )
        MEDIUM = (
            "MEDIUM",
            "Medium",
        )
        HIGH = (
            "HIGH",
            "High",
        )
        CRITICAL = (
            "CRITICAL",
            "Critical",
        )

    class Status(models.TextChoices):
        OPEN = (
            "OPEN",
            "Open",
        )
        ASSIGNED = (
            "ASSIGNED",
            "Assigned",
        )
        UNDER_INVESTIGATION = (
            "UNDER_INVESTIGATION",
            "Under Investigation",
        )
        EVIDENCE_COLLECTION = (
            "EVIDENCE_COLLECTION",
            "Evidence Collection",
        )
        AI_ANALYSIS = (
            "AI_ANALYSIS",
            "AI Analysis",
        )
        REPORT_GENERATION = (
            "REPORT_GENERATION",
            "Report Generation",
        )
        CLOSED = (
            "CLOSED",
            "Closed",
        )
        ARCHIVED = (
            "ARCHIVED",
            "Archived",
        )

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="Case ID",
    )

    case_number = models.CharField(
        max_length=40,
        unique=True,
        default=generate_case_number,
        editable=False,
        verbose_name="Case Number",
        help_text="Automatically generated unique case number.",
    )

    case_title = models.CharField(
        max_length=200,
        verbose_name="Case Title",
        help_text="Enter a clear and descriptive title for the case.",
    )

    description = models.TextField(
        verbose_name="Case Description",
        help_text="Provide complete details about the cyber-crime case.",
    )

    crime_category = models.CharField(
        max_length=30,
        choices=CrimeCategory.choices,
        default=CrimeCategory.OTHER,
        db_index=True,
        verbose_name="Crime Category",
    )

    priority = models.CharField(
        max_length=10,
        choices=Priority.choices,
        default=Priority.MEDIUM,
        db_index=True,
        verbose_name="Priority Level",
    )

    status = models.CharField(
        max_length=30,
        choices=Status.choices,
        default=Status.OPEN,
        db_index=True,
        verbose_name="Case Status",
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_cases",
        verbose_name="Created By",
        help_text="User who registered the case in the AIDEX system.",
    )

    assigned_investigator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="assigned_cases",
        null=True,
        blank=True,
        verbose_name="Assigned Investigator",
        help_text="Investigator responsible for handling the case.",
    )

    created_date = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name="Created Date",
    )

    updated_date = models.DateTimeField(
        auto_now=True,
        verbose_name="Updated Date",
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name="Active Case",
        help_text="Inactive cases remain stored for audit purposes.",
    )

    # ------------------------------------------------------------------
    # Archive / Restore metadata
    # ------------------------------------------------------------------

    pre_archive_status = models.CharField(
        max_length=30,
        choices=Status.choices,
        blank=True,
        editable=False,
        verbose_name="Status Before Archive",
        help_text=(
            "Stores the case status immediately before archival so the "
            "case can be restored to the correct workflow state."
        ),
    )

    archive_reason = models.TextField(
        blank=True,
        editable=False,
        verbose_name="Archive Reason",
    )

    archived_at = models.DateTimeField(
        null=True,
        blank=True,
        editable=False,
        verbose_name="Archived At",
    )

    archived_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="archived_cases",
        null=True,
        blank=True,
        editable=False,
        verbose_name="Archived By",
    )

    class Meta:
        db_table = "aidex_cases"

        ordering = (
            "-created_date",
        )

        get_latest_by = "created_date"

        verbose_name = "Cyber Crime Case"
        verbose_name_plural = "Cyber Crime Cases"

        indexes = [
            models.Index(
                fields=[
                    "status",
                    "priority",
                ],
                name="case_status_priority_idx",
            ),
            models.Index(
                fields=[
                    "assigned_investigator",
                    "status",
                ],
                name="case_assignee_status_idx",
            ),
            models.Index(
                fields=[
                    "crime_category",
                    "status",
                ],
                name="case_category_status_idx",
            ),
        ]

        permissions = [
            (
                "assign_case",
                "Can assign case to investigator",
            ),
            (
                "close_case",
                "Can close cyber crime case",
            ),
            (
                "archive_case",
                "Can archive cyber crime case",
            ),
            (
                "restore_case",
                "Can restore archived cyber crime case",
            ),
            (
                "view_case_statistics",
                "Can view case statistics",
            ),
        ]

    def clean(self):
        """
        Perform model-level validation before saving.
        """
        super().clean()

        if self.case_title:
            self.case_title = self.case_title.strip()

        if self.description:
            self.description = self.description.strip()

        if self.archive_reason:
            self.archive_reason = self.archive_reason.strip()

        if not self.case_title:
            raise ValidationError({
                "case_title": "Case title cannot be empty.",
            })

        if not self.description:
            raise ValidationError({
                "description": "Case description cannot be empty.",
            })

        if (
            self.assigned_investigator
            and not self.assigned_investigator.is_active
        ):
            raise ValidationError({
                "assigned_investigator": (
                    "An inactive user cannot be assigned to a case."
                ),
            })

        # Keep archive lifecycle state internally consistent.
        if (
            self.status == self.Status.ARCHIVED
            and self.is_active
        ):
            raise ValidationError({
                "is_active": (
                    "An archived case must be inactive."
                ),
            })

        if (
            self.status != self.Status.ARCHIVED
            and not self.is_active
        ):
            raise ValidationError({
                "is_active": (
                    "A non-archived case must remain active."
                ),
            })

        if (
            self.pre_archive_status
            == self.Status.ARCHIVED
        ):
            raise ValidationError({
                "pre_archive_status": (
                    "The pre-archive status cannot itself be Archived."
                ),
            })

    def save(self, *args, **kwargs):
        """
        Validate and normalize case data before saving.

        Archive/restore lifecycle fields are intentionally not inferred here.
        The archive and restore views set them explicitly so the responsible
        user and reason remain auditable.
        """
        if self.case_title:
            self.case_title = self.case_title.strip()

        if self.description:
            self.description = self.description.strip()

        if self.archive_reason:
            self.archive_reason = self.archive_reason.strip()

        self.full_clean()

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.case_number} | {self.case_title}"

    @property
    def is_closed(self):
        return self.status in {
            self.Status.CLOSED,
            self.Status.ARCHIVED,
        }

    @property
    def is_high_priority(self):
        return self.priority in {
            self.Priority.HIGH,
            self.Priority.CRITICAL,
        }

    @property
    def is_archived(self):
        return (
            self.status == self.Status.ARCHIVED
            and not self.is_active
        )

    @property
    def restore_status(self):
        """
        Return the safest status to use when restoring an archived case.

        New archive operations preserve pre_archive_status. Legacy archived
        records created before this field existed fall back to OPEN.
        """
        if (
            self.pre_archive_status
            and self.pre_archive_status != self.Status.ARCHIVED
        ):
            return self.pre_archive_status

        return self.Status.OPEN