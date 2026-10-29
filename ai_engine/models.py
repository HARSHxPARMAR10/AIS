"""
AIDEX AI Engine Models

This module stores AI-assisted forensic analysis records for digital
evidence. It is designed for a cost-conscious multi-provider integration
where:

- AI requests run only when explicitly triggered.
- Completed results are stored and reused.
- Token usage and API attempts are tracked.
- Errors and quota failures are preserved for audit and troubleshooting.
- Large evidence files are represented through extracted or reduced inputs,
  rather than being sent directly to an external AI provider.

The models are provider-agnostic and can support future OCR, object
detection, malware analysis, audio transcription and other services.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

from evidence.models import Evidence


# ==========================================================
# Utility Functions
# ==========================================================

def generate_analysis_number() -> str:
    """
    Generate a readable analysis number.

    Example:
        AIA-20260805-7D3F9A21
    """

    date_part = timezone.now().strftime("%Y%m%d")
    unique_part = uuid.uuid4().hex[:8].upper()

    return f"AIA-{date_part}-{unique_part}"


# ==========================================================
# Main AI Analysis Model
# ==========================================================

class AIAnalysis(models.Model):
    """
    Stores one AI-assisted forensic analysis for an evidence record.

    A completed record acts as a cache of the AI result. The application
    should not call the AI provider while simply opening list or detail
    pages. A new provider request should only occur when the user explicitly
    starts or re-runs an analysis.
    """

    class AnalysisType(models.TextChoices):
        GENERAL = "GENERAL", "General Evidence Analysis"
        OCR = "OCR", "OCR Text Extraction"
        DOCUMENT = "DOCUMENT", "Document Analysis"
        IMAGE = "IMAGE", "Image Analysis"
        VIDEO = "VIDEO", "Video Analysis"
        AUDIO = "AUDIO", "Audio Analysis"
        FACE_DETECTION = "FACE_DETECTION", "Face Detection"
        OBJECT_DETECTION = "OBJECT_DETECTION", "Object Detection"
        METADATA = "METADATA", "Metadata Analysis"
        FILE_INTEGRITY = "FILE_INTEGRITY", "File Integrity Analysis"
        MALWARE = "MALWARE", "Malware Analysis"
        EMAIL = "EMAIL", "Email Analysis"
        CHAT = "CHAT", "Chat Analysis"
        LOG = "LOG", "Log Analysis"
        NETWORK = "NETWORK", "Network Analysis"
        KEYWORD_EXTRACTION = "KEYWORD_EXTRACTION", "Keyword Extraction"
        THREAT_ASSESSMENT = "THREAT_ASSESSMENT", "Threat Assessment"
        CUSTOM = "CUSTOM", "Custom AI Analysis"

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        QUEUED = "QUEUED", "Queued"
        PROCESSING = "PROCESSING", "Processing"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    class Priority(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class ThreatLevel(models.TextChoices):
        UNKNOWN = "UNKNOWN", "Unknown"
        NONE = "NONE", "No Threat"
        LOW = "LOW", "Low Threat"
        MEDIUM = "MEDIUM", "Medium Threat"
        HIGH = "HIGH", "High Threat"
        CRITICAL = "CRITICAL", "Critical Threat"

    class Provider(models.TextChoices):
        GEMINI = "GEMINI", "Google Gemini"
        OPENROUTER = "OPENROUTER", "OpenRouter (ChatGPT / GPT-4o)"
        LOCAL = "LOCAL", "Local AI Service"
        MANUAL = "MANUAL", "Manual Analysis"
        OTHER = "OTHER", "Other Provider"

    class CacheStatus(models.TextChoices):
        NOT_CACHED = "NOT_CACHED", "Not Cached"
        CACHED = "CACHED", "Cached Result"
        INVALIDATED = "INVALIDATED", "Cache Invalidated"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="Analysis ID",
    )

    analysis_number = models.CharField(
        max_length=40,
        unique=True,
        default=generate_analysis_number,
        editable=False,
        db_index=True,
        verbose_name="Analysis Number",
    )

    evidence = models.ForeignKey(
        Evidence,
        on_delete=models.PROTECT,
        related_name="ai_analyses",
        verbose_name="Related Evidence",
        help_text="Digital evidence analyzed by the AI engine.",
    )

    title = models.CharField(
        max_length=200,
        verbose_name="Analysis Title",
        help_text="Enter a clear title describing the requested analysis.",
    )

    analysis_type = models.CharField(
        max_length=30,
        choices=AnalysisType.choices,
        default=AnalysisType.GENERAL,
        db_index=True,
        verbose_name="Analysis Type",
    )

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
        verbose_name="Analysis Status",
    )

    priority = models.CharField(
        max_length=12,
        choices=Priority.choices,
        default=Priority.MEDIUM,
        db_index=True,
        verbose_name="Processing Priority",
    )

    threat_level = models.CharField(
        max_length=12,
        choices=ThreatLevel.choices,
        default=ThreatLevel.UNKNOWN,
        db_index=True,
        verbose_name="Threat Level",
    )

    provider = models.CharField(
        max_length=20,
        choices=Provider.choices,
        default=Provider.GEMINI,
        db_index=True,
        verbose_name="AI Provider",
    )

    model_name = models.CharField(
        max_length=100,
        blank=True,
        verbose_name="AI Model Name",
        help_text=(
            "Provider model used for this run. Keep configurable in settings."
        ),
    )

    prompt_version = models.CharField(
        max_length=40,
        default="v1",
        verbose_name="Prompt Version",
    )

    request_prompt = models.TextField(
        blank=True,
        verbose_name="Request Prompt",
        help_text=(
            "Final prompt submitted to the provider after sanitization."
        ),
    )

    input_summary = models.TextField(
        blank=True,
        verbose_name="Input Summary",
        help_text=(
            "Reduced or extracted input used for large evidence files."
        ),
    )

    ai_summary = models.TextField(
        blank=True,
        verbose_name="AI Summary",
    )

    extracted_text = models.TextField(
        blank=True,
        verbose_name="Extracted Text",
        help_text="OCR, transcription or parsed textual content.",
    )

    extracted_keywords = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Extracted Keywords",
        help_text="JSON list of keywords or entities.",
    )

    detected_entities = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Detected Entities",
        help_text="JSON list of detected people, organizations or indicators.",
    )

    findings = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Structured Findings",
        help_text="JSON list of structured forensic findings.",
    )

    recommendations = models.TextField(
        blank=True,
        verbose_name="Recommendations",
    )

    provider_response = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Provider Response",
        help_text=(
            "Sanitized structured response retained for troubleshooting."
        ),
    )

    confidence_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[
            MinValueValidator(Decimal("0.00")),
            MaxValueValidator(Decimal("100.00")),
        ],
        verbose_name="Confidence Score",
        help_text="Confidence percentage from 0 to 100.",
    )

    risk_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[
            MinValueValidator(Decimal("0.00")),
            MaxValueValidator(Decimal("100.00")),
        ],
        verbose_name="Risk Score",
        help_text="Risk percentage from 0 to 100.",
    )

    input_tokens = models.PositiveIntegerField(
        default=0,
        verbose_name="Input Tokens",
    )

    output_tokens = models.PositiveIntegerField(
        default=0,
        verbose_name="Output Tokens",
    )

    total_tokens = models.PositiveIntegerField(
        default=0,
        verbose_name="Total Tokens",
    )

    api_attempts = models.PositiveSmallIntegerField(
        default=0,
        verbose_name="API Attempts",
    )

    max_api_attempts = models.PositiveSmallIntegerField(
        default=2,
        validators=[
            MinValueValidator(1),
        ],
        verbose_name="Maximum API Attempts",
    )

    processing_time_seconds = models.DecimalField(
        max_digits=12,
        decimal_places=3,
        null=True,
        blank=True,
        validators=[
            MinValueValidator(Decimal("0.000")),
        ],
        verbose_name="Processing Time in Seconds",
    )

    started_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Started At",
    )

    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Completed At",
    )

    last_error = models.TextField(
        blank=True,
        verbose_name="Last Error",
    )

    provider_error_code = models.CharField(
        max_length=80,
        blank=True,
        verbose_name="Provider Error Code",
    )

    quota_exceeded = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name="Quota Exceeded",
    )

    cached_result = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name="Cached Result",
    )

    cache_status = models.CharField(
        max_length=20,
        choices=CacheStatus.choices,
        default=CacheStatus.NOT_CACHED,
        db_index=True,
        verbose_name="Cache Status",
    )

    cache_key = models.CharField(
        max_length=128,
        blank=True,
        db_index=True,
        verbose_name="Cache Key",
        help_text=(
            "May combine evidence hash, analysis type and prompt version."
        ),
    )

    evidence_hash_at_analysis = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        verbose_name="Evidence Hash at Analysis",
        help_text=(
            "SHA-256 hash recorded when this analysis was created."
        ),
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_ai_analyses",
        verbose_name="Created By",
    )

    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="reviewed_ai_analyses",
        null=True,
        blank=True,
        verbose_name="Reviewed By",
    )

    reviewed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Reviewed At",
    )

    review_notes = models.TextField(
        blank=True,
        verbose_name="Review Notes",
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
        verbose_name="Active Analysis",
    )

    class Meta:
        db_table = "aidex_ai_analysis"

        ordering = (
            "-created_date",
        )

        get_latest_by = "created_date"

        verbose_name = "AI Evidence Analysis"
        verbose_name_plural = "AI Evidence Analyses"

        indexes = [
            models.Index(
                fields=[
                    "evidence",
                    "status",
                ],
                name="aia_evidence_status_idx",
            ),
            models.Index(
                fields=[
                    "analysis_type",
                    "status",
                ],
                name="aia_type_status_idx",
            ),
            models.Index(
                fields=[
                    "provider",
                    "model_name",
                ],
                name="aia_provider_model_idx",
            ),
            models.Index(
                fields=[
                    "created_by",
                    "created_date",
                ],
                name="aia_creator_date_idx",
            ),
            models.Index(
                fields=[
                    "threat_level",
                    "risk_score",
                ],
                name="aia_threat_risk_idx",
            ),
            models.Index(
                fields=[
                    "quota_exceeded",
                    "status",
                ],
                name="aia_quota_status_idx",
            ),
        ]

        permissions = [
            (
                "run_ai_analysis",
                "Can run AI evidence analysis",
            ),
            (
                "rerun_ai_analysis",
                "Can re-run AI evidence analysis",
            ),
            (
                "cancel_ai_analysis",
                "Can cancel AI evidence analysis",
            ),
            (
                "review_ai_analysis",
                "Can review AI evidence analysis",
            ),
            (
                "archive_ai_analysis",
                "Can archive AI evidence analysis",
            ),
            (
                "restore_ai_analysis",
                "Can restore AI evidence analysis",
            ),
            (
                "view_ai_usage",
                "Can view AI token and provider usage",
            ),
        ]

        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(confidence_score__isnull=True)
                    | (
                        models.Q(confidence_score__gte=0)
                        & models.Q(confidence_score__lte=100)
                    )
                ),
                name="aia_confidence_range_ck",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(risk_score__isnull=True)
                    | (
                        models.Q(risk_score__gte=0)
                        & models.Q(risk_score__lte=100)
                    )
                ),
                name="aia_risk_range_ck",
            ),
            models.CheckConstraint(
                condition=models.Q(max_api_attempts__gte=1),
                name="aia_max_attempts_gte_1_ck",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    api_attempts__lte=models.F("max_api_attempts")
                ),
                name="aia_attempts_lte_max_ck",
            ),
        ]

    def clean(self) -> None:
        """
        Perform model-level validation and normalization.
        """

        super().clean()

        if self.title:
            self.title = " ".join(self.title.strip().split())

        if self.model_name:
            self.model_name = self.model_name.strip()

        if self.prompt_version:
            self.prompt_version = self.prompt_version.strip()

        if self.request_prompt:
            self.request_prompt = self.request_prompt.strip()

        if self.input_summary:
            self.input_summary = self.input_summary.strip()

        if self.ai_summary:
            self.ai_summary = self.ai_summary.strip()

        if self.extracted_text:
            self.extracted_text = self.extracted_text.strip()

        if self.recommendations:
            self.recommendations = self.recommendations.strip()

        if self.last_error:
            self.last_error = self.last_error.strip()

        if self.review_notes:
            self.review_notes = self.review_notes.strip()

        if not self.title:
            raise ValidationError({
                "title": "Analysis title cannot be empty.",
            })

        if len(self.title) < 5:
            raise ValidationError({
                "title": (
                    "Analysis title must contain at least 5 characters."
                ),
            })

        if self.evidence_id and not self.evidence.is_active:
            raise ValidationError({
                "evidence": (
                    "AI analysis cannot be created for archived evidence."
                ),
            })

        if self.max_api_attempts == 0:
            raise ValidationError({
                "max_api_attempts": (
                    "Maximum API attempts must be at least 1."
                ),
            })

        if self.api_attempts > self.max_api_attempts:
            raise ValidationError({
                "api_attempts": (
                    "API attempts cannot exceed the configured maximum."
                ),
            })

        if (
            self.status == self.Status.PROCESSING
            and self.started_at is None
        ):
            raise ValidationError({
                "started_at": (
                    "Processing analyses must have a start timestamp."
                ),
            })

        if self.status == self.Status.COMPLETED:
            completed_errors = {}

            if self.completed_at is None:
                completed_errors[
                    "completed_at"
                ] = "Completed analyses require a completion timestamp."

            if not self.ai_summary:
                completed_errors[
                    "ai_summary"
                ] = "Completed analyses require an AI summary."

            if completed_errors:
                raise ValidationError(
                    completed_errors
                )

        if (
            self.status == self.Status.FAILED
            and not self.last_error
        ):
            raise ValidationError({
                "last_error": (
                    "Failed analyses must store an error message."
                ),
            })

        if self.reviewed_by and not self.reviewed_at:
            raise ValidationError({
                "reviewed_at": (
                    "Reviewed analyses require a review timestamp."
                ),
            })

        if self.reviewed_at and not self.reviewed_by:
            raise ValidationError({
                "reviewed_by": (
                    "A reviewer must be selected when review time is set."
                ),
            })

        expected_total = (
            self.input_tokens
            + self.output_tokens
        )

        if self.total_tokens != expected_total:
            raise ValidationError({
                "total_tokens": (
                    "Total tokens must equal input tokens plus output tokens."
                ),
            })

    def save(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Normalize values and keep derived fields synchronized.

        When callers use update_fields, derived fields changed by this method
        are added automatically so partial updates cannot leave stale token,
        cache or lifecycle metadata in the database.
        """

        if self.title:
            self.title = " ".join(self.title.strip().split())

        if self.model_name:
            self.model_name = self.model_name.strip()

        if self.prompt_version:
            self.prompt_version = self.prompt_version.strip()

        self.total_tokens = (
            self.input_tokens
            + self.output_tokens
        )

        if self.evidence_id and not self.evidence_hash_at_analysis:
            self.evidence_hash_at_analysis = (
                self.evidence.sha256_hash
                or ""
            )

        if self.cache_status == self.CacheStatus.CACHED:
            self.cached_result = True

        elif self.cache_status in {
            self.CacheStatus.NOT_CACHED,
            self.CacheStatus.INVALIDATED,
        }:
            self.cached_result = False

        if self.cached_result:
            self.cache_status = self.CacheStatus.CACHED

        if (
            self.status in {
                self.Status.COMPLETED,
                self.Status.FAILED,
                self.Status.CANCELLED,
            }
            and self.completed_at is None
        ):
            self.completed_at = timezone.now()

        if (
            self.status == self.Status.PROCESSING
            and self.started_at is None
        ):
            self.started_at = timezone.now()

        update_fields = kwargs.get(
            "update_fields"
        )

        if update_fields is not None:
            synchronized_fields = set(
                update_fields
            )

            if {
                "input_tokens",
                "output_tokens",
            } & synchronized_fields:
                synchronized_fields.add(
                    "total_tokens"
                )

            if (
                "evidence" in synchronized_fields
                or "evidence_hash_at_analysis" in synchronized_fields
            ):
                synchronized_fields.add(
                    "evidence_hash_at_analysis"
                )

            if {
                "cache_status",
                "cached_result",
            } & synchronized_fields:
                synchronized_fields.update({
                    "cache_status",
                    "cached_result",
                })

            if "status" in synchronized_fields:
                synchronized_fields.update({
                    "started_at",
                    "completed_at",
                })

            kwargs[
                "update_fields"
            ] = list(
                synchronized_fields
            )

        self.full_clean()

        super().save(
            *args,
            **kwargs,
        )


    def __str__(self) -> str:
        return (
            f"{self.analysis_number} | "
            f"{self.title}"
        )

    @property
    def case(self):
        """
        Return the case linked through the evidence record.
        """

        return self.evidence.case

    @property
    def is_completed(self) -> bool:
        return self.status == self.Status.COMPLETED

    @property
    def is_processing(self) -> bool:
        return self.status == self.Status.PROCESSING

    @property
    def is_failed(self) -> bool:
        return self.status == self.Status.FAILED

    @property
    def is_final(self) -> bool:
        return self.status in {
            self.Status.COMPLETED,
            self.Status.FAILED,
            self.Status.CANCELLED,
        }

    @property
    def retry_budget_exhausted(self) -> bool:
        """
        Return whether the current automatic/provider attempt budget
        has been consumed.

        This is informational only. A deliberate manual retry starts a
        fresh attempt cycle in the retry workflow, so exhausting the
        previous cycle must not permanently hide or block Retry.
        """

        return self.api_attempts >= self.max_api_attempts

    @property
    def can_retry(self) -> bool:
        """
        Return whether a failed analysis is eligible for a manual retry.

        Manual retry eligibility is intentionally independent of the
        previous run's api_attempts value. The retry view resets the attempt
        counter before queueing the new run.

        Quota failures remain blocked until handled explicitly, because
        immediately retrying a provider quota failure can waste requests.
        """

        return (
            self.status == self.Status.FAILED
            and not self.quota_exceeded
            and self.is_active
            and self.evidence.is_active
        )

    @property
    def has_provider_result(self) -> bool:
        return bool(
            self.ai_summary
            or self.provider_response
            or self.extracted_text
            or self.findings
        )

    @property
    def result_is_stale(self) -> bool:
        """
        Return True when the evidence hash changed after analysis.
        """

        current_hash = (
            self.evidence.sha256_hash
            or ""
        )

        return bool(
            self.evidence_hash_at_analysis
            and current_hash
            and self.evidence_hash_at_analysis != current_hash
        )

    @property
    def processing_duration(self):
        """
        Return elapsed processing duration when timestamps exist.
        """

        if not self.started_at:
            return None

        end_time = (
            self.completed_at
            or timezone.now()
        )

        return end_time - self.started_at

    @property
    def risk_category(self) -> str:
        """
        Return a display-friendly risk category based on risk score.
        """

        if self.risk_score is None:
            return "Unknown"

        score = float(
            self.risk_score
        )

        if score >= 80:
            return "Critical"

        if score >= 60:
            return "High"

        if score >= 30:
            return "Medium"

        if score > 0:
            return "Low"

        return "None"

    @property
    def keyword_count(self) -> int:
        if isinstance(
            self.extracted_keywords,
            list,
        ):
            return len(
                self.extracted_keywords
            )

        return 0

    @property
    def finding_count(self) -> int:
        if isinstance(
            self.findings,
            list,
        ):
            return len(
                self.findings
            )

        return 0


# ==========================================================
# AI Analysis Event Log
# ==========================================================

class AIAnalysisLog(models.Model):
    """
    Stores an append-only style event history for an AI analysis.

    The application should create log records for meaningful state changes,
    provider requests, retries, failures, completion, review and archiving.
    """

    class EventType(models.TextChoices):
        CREATED = "CREATED", "Created"
        QUEUED = "QUEUED", "Queued"
        STARTED = "STARTED", "Started"
        PROVIDER_REQUEST = "PROVIDER_REQUEST", "Provider Request"
        PROVIDER_RESPONSE = "PROVIDER_RESPONSE", "Provider Response"
        RETRY = "RETRY", "Retry"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"
        REVIEWED = "REVIEWED", "Reviewed"
        CACHE_HIT = "CACHE_HIT", "Cache Hit"
        CACHE_INVALIDATED = "CACHE_INVALIDATED", "Cache Invalidated"
        ARCHIVED = "ARCHIVED", "Archived"
        RESTORED = "RESTORED", "Restored"
        NOTE = "NOTE", "Note"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="Log ID",
    )

    analysis = models.ForeignKey(
        AIAnalysis,
        on_delete=models.CASCADE,
        related_name="logs",
        verbose_name="AI Analysis",
    )

    event_type = models.CharField(
        max_length=30,
        choices=EventType.choices,
        db_index=True,
        verbose_name="Event Type",
    )

    message = models.TextField(
        verbose_name="Event Message",
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Event Metadata",
    )

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="ai_analysis_logs",
        null=True,
        blank=True,
        verbose_name="Actor",
    )

    provider = models.CharField(
        max_length=20,
        choices=AIAnalysis.Provider.choices,
        blank=True,
        verbose_name="Provider",
    )

    provider_request_id = models.CharField(
        max_length=150,
        blank=True,
        db_index=True,
        verbose_name="Provider Request ID",
    )

    created_date = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name="Created Date",
    )

    class Meta:
        db_table = "aidex_ai_analysis_logs"

        ordering = (
            "-created_date",
        )

        verbose_name = "AI Analysis Log"
        verbose_name_plural = "AI Analysis Logs"

        indexes = [
            models.Index(
                fields=[
                    "analysis",
                    "created_date",
                ],
                name="aialog_analysis_date_idx",
            ),
            models.Index(
                fields=[
                    "event_type",
                    "created_date",
                ],
                name="aialog_event_date_idx",
            ),
        ]

    def clean(self) -> None:
        super().clean()

        if self.message:
            self.message = self.message.strip()

        if not self.message:
            raise ValidationError({
                "message": "Log message cannot be empty.",
            })

    def save(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if self.message:
            self.message = self.message.strip()

        self.full_clean()

        super().save(
            *args,
            **kwargs,
        )

    def __str__(self) -> str:
        return (
            f"{self.analysis.analysis_number} | "
            f"{self.get_event_type_display()}"
        )
