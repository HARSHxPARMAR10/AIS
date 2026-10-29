"""
AIDEX AI Engine Administration

Ultra-professional Django admin configuration for:

- AIAnalysis
- AIAnalysisLog

Features:

- Role-aware read/write controls
- Advanced list displays and filters
- Search across case, evidence and analysis metadata
- Read-only forensic fields
- Safe bulk actions
- Token and risk visibility
- Audit-log inspection
- Provider and cache diagnostics
- Fieldset organization
- Optimized querysets using select_related
"""

from __future__ import annotations

from typing import Any

from django.contrib import admin, messages
from django.contrib.admin import SimpleListFilter
from django.db import transaction
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils import timezone
from django.utils.html import format_html

from .models import AIAnalysis, AIAnalysisLog
from .services import (
    AIAnalysisStateError,
    archive_analysis,
    cancel_analysis,
    create_analysis_log,
    restore_analysis,
)


# ==========================================================
# Shared Helpers
# ==========================================================

ROLE_ADMINISTRATOR = "ADMINISTRATOR"
ROLE_CYBER_OFFICER = "CYBER_OFFICER"


def normalize_role(
    role_value: Any,
) -> str:
    """
    Normalize a role value to the standard AIDEX format.
    """

    return (
        str(role_value or "")
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )


def is_ai_admin_user(
    user: Any,
) -> bool:
    """
    Return whether a user may manage AI Engine records in Django admin.
    """

    if getattr(
        user,
        "is_superuser",
        False,
    ):
        return True

    return normalize_role(
        getattr(
            user,
            "role",
            "",
        )
    ) in {
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    }


def format_score_badge(
    value: Any,
    *,
    kind: str,
) -> str:
    """
    Render confidence or risk score as a colored admin badge.
    """

    if value is None:
        return format_html(
            '<span style="color:#64748b;font-weight:700;">—</span>'
        )

    numeric_value = float(
        value
    )

    if kind == "risk":
        if numeric_value >= 80:
            background = "#fee2e2"
            color = "#991b1b"
        elif numeric_value >= 60:
            background = "#ffedd5"
            color = "#9a3412"
        elif numeric_value >= 30:
            background = "#fef3c7"
            color = "#92400e"
        else:
            background = "#dcfce7"
            color = "#166534"

    else:
        if numeric_value >= 80:
            background = "#dcfce7"
            color = "#166534"
        elif numeric_value >= 60:
            background = "#dbeafe"
            color = "#1d4ed8"
        elif numeric_value >= 30:
            background = "#fef3c7"
            color = "#92400e"
        else:
            background = "#fee2e2"
            color = "#991b1b"

    return format_html(
        (
            '<span style="display:inline-flex;align-items:center;'
            'padding:4px 9px;border-radius:999px;'
            'background:{};color:{};font-weight:800;">'
            '{}%</span>'
        ),
        background,
        color,
        f"{numeric_value:.2f}",
    )


# ==========================================================
# Custom Admin Filters
# ==========================================================

class RiskBandFilter(SimpleListFilter):
    """
    Filter analyses by practical risk-score bands.
    """

    title = "Risk Band"
    parameter_name = "risk_band"

    def lookups(
        self,
        request: HttpRequest,
        model_admin: admin.ModelAdmin,
    ):
        return (
            (
                "critical",
                "Critical (80-100)",
            ),
            (
                "high",
                "High (60-79.99)",
            ),
            (
                "medium",
                "Medium (30-59.99)",
            ),
            (
                "low",
                "Low (0-29.99)",
            ),
            (
                "unknown",
                "Unknown",
            ),
        )

    def queryset(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ):
        selected_value = self.value()

        if selected_value == "critical":
            return queryset.filter(
                risk_score__gte=80
            )

        if selected_value == "high":
            return queryset.filter(
                risk_score__gte=60,
                risk_score__lt=80,
            )

        if selected_value == "medium":
            return queryset.filter(
                risk_score__gte=30,
                risk_score__lt=60,
            )

        if selected_value == "low":
            return queryset.filter(
                risk_score__gte=0,
                risk_score__lt=30,
            )

        if selected_value == "unknown":
            return queryset.filter(
                risk_score__isnull=True
            )

        return queryset


class ConfidenceBandFilter(SimpleListFilter):
    """
    Filter analyses by confidence-score bands.
    """

    title = "Confidence Band"
    parameter_name = "confidence_band"

    def lookups(
        self,
        request: HttpRequest,
        model_admin: admin.ModelAdmin,
    ):
        return (
            (
                "high",
                "High (80-100)",
            ),
            (
                "moderate",
                "Moderate (60-79.99)",
            ),
            (
                "low",
                "Low (0-59.99)",
            ),
            (
                "unknown",
                "Unknown",
            ),
        )

    def queryset(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ):
        selected_value = self.value()

        if selected_value == "high":
            return queryset.filter(
                confidence_score__gte=80
            )

        if selected_value == "moderate":
            return queryset.filter(
                confidence_score__gte=60,
                confidence_score__lt=80,
            )

        if selected_value == "low":
            return queryset.filter(
                confidence_score__gte=0,
                confidence_score__lt=60,
            )

        if selected_value == "unknown":
            return queryset.filter(
                confidence_score__isnull=True
            )

        return queryset


class CacheHealthFilter(SimpleListFilter):
    """
    Filter cached, fresh and stale analysis results.
    """

    title = "Cache Health"
    parameter_name = "cache_health"

    def lookups(
        self,
        request: HttpRequest,
        model_admin: admin.ModelAdmin,
    ):
        return (
            (
                "cached",
                "Cached",
            ),
            (
                "fresh",
                "Fresh",
            ),
            (
                "stale",
                "Stale Hash",
            ),
            (
                "invalidated",
                "Invalidated",
            ),
        )

    def queryset(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ):
        selected_value = self.value()

        if selected_value == "cached":
            return queryset.filter(
                cached_result=True
            )

        if selected_value == "fresh":
            return queryset.filter(
                cached_result=False,
                cache_status=AIAnalysis.CacheStatus.NOT_CACHED,
            )

        if selected_value == "invalidated":
            return queryset.filter(
                cache_status=AIAnalysis.CacheStatus.INVALIDATED
            )

        if selected_value == "stale":
            stale_ids = [
                analysis.pk
                for analysis in queryset.select_related(
                    "evidence"
                )
                if analysis.result_is_stale
            ]

            return queryset.filter(
                pk__in=stale_ids
            )

        return queryset


# ==========================================================
# AI Analysis Admin
# ==========================================================

@admin.register(AIAnalysis)
class AIAnalysisAdmin(admin.ModelAdmin):
    """
    Administrative interface for AI-assisted forensic analyses.
    """

    list_display = (
        "analysis_number",
        "title",
        "evidence_reference",
        "analysis_type_badge",
        "status_badge",
        "priority_badge",
        "threat_badge",
        "risk_score_badge",
        "confidence_score_badge",
        "provider_display",
        "token_total",
        "cache_badge",
        "created_by_display",
        "created_date",
        "active_badge",
    )

    list_display_links = (
        "analysis_number",
        "title",
    )

    list_filter = (
        "status",
        "analysis_type",
        "priority",
        "threat_level",
        "provider",
        "cache_status",
        "cached_result",
        "quota_exceeded",
        "is_active",
        RiskBandFilter,
        ConfidenceBandFilter,
        CacheHealthFilter,
        "created_date",
        "completed_at",
    )

    search_fields = (
        "analysis_number",
        "title",
        "request_prompt",
        "ai_summary",
        "extracted_text",
        "recommendations",
        "model_name",
        "provider_error_code",
        "last_error",
        "evidence__evidence_title",
        "evidence__original_filename",
        "evidence__sha256_hash",
        "evidence__case__case_number",
        "evidence__case__case_title",
        "created_by__username",
        "created_by__full_name",
        "reviewed_by__username",
        "reviewed_by__full_name",
    )

    ordering = (
        "-created_date",
    )

    date_hierarchy = "created_date"

    list_per_page = 30

    list_max_show_all = 300

    save_on_top = True

    show_full_result_count = False

    autocomplete_fields = (
        "created_by",
        "reviewed_by",
    )

    raw_id_fields = (
        "evidence",
    )

    readonly_fields = (
        "id",
        "analysis_number",
        "case_reference",
        "evidence_hash_at_analysis",
        "current_evidence_hash",
        "stale_result_display",
        "token_usage_display",
        "processing_duration_display",
        "created_date",
        "updated_date",
    )

    fieldsets = (
        (
            "Analysis Identity",
            {
                "fields": (
                    "id",
                    "analysis_number",
                    "title",
                    "evidence",
                    "case_reference",
                    "analysis_type",
                    "priority",
                    "status",
                    "is_active",
                )
            },
        ),
        (
            "Provider Configuration",
            {
                "fields": (
                    "provider",
                    "model_name",
                    "prompt_version",
                    "request_prompt",
                    "input_summary",
                )
            },
        ),
        (
            "AI Result",
            {
                "fields": (
                    "ai_summary",
                    "extracted_text",
                    "extracted_keywords",
                    "detected_entities",
                    "findings",
                    "recommendations",
                    "provider_response",
                )
            },
        ),
        (
            "Scoring and Threat Assessment",
            {
                "fields": (
                    "confidence_score",
                    "risk_score",
                    "threat_level",
                )
            },
        ),
        (
            "Usage and Retry Tracking",
            {
                "fields": (
                    "input_tokens",
                    "output_tokens",
                    "total_tokens",
                    "token_usage_display",
                    "api_attempts",
                    "max_api_attempts",
                    "quota_exceeded",
                )
            },
        ),
        (
            "Cache and Integrity",
            {
                "fields": (
                    "cached_result",
                    "cache_status",
                    "cache_key",
                    "evidence_hash_at_analysis",
                    "current_evidence_hash",
                    "stale_result_display",
                )
            },
        ),
        (
            "Execution Timing",
            {
                "fields": (
                    "started_at",
                    "completed_at",
                    "processing_time_seconds",
                    "processing_duration_display",
                )
            },
        ),
        (
            "Errors and Diagnostics",
            {
                "classes": (
                    "collapse",
                ),
                "fields": (
                    "last_error",
                    "provider_error_code",
                ),
            },
        ),
        (
            "Human Review",
            {
                "fields": (
                    "reviewed_by",
                    "reviewed_at",
                    "review_notes",
                )
            },
        ),
        (
            "Ownership and Audit",
            {
                "fields": (
                    "created_by",
                    "created_date",
                    "updated_date",
                )
            },
        ),
    )

    actions = (
        "mark_pending",
        "mark_cancelled",
        "archive_selected",
        "restore_selected",
        "invalidate_cache",
        "clear_quota_flag",
    )

    def get_queryset(
        self,
        request: HttpRequest,
    ) -> QuerySet:
        """
        Optimize related-object access for changelist rendering.
        """

        queryset = super().get_queryset(
            request
        )

        return queryset.select_related(
            "evidence",
            "evidence__case",
            "evidence__uploaded_by",
            "created_by",
            "reviewed_by",
        )

    def has_module_permission(
        self,
        request: HttpRequest,
    ) -> bool:
        return is_ai_admin_user(
            request.user
        )

    def has_view_permission(
        self,
        request: HttpRequest,
        obj: AIAnalysis | None = None,
    ) -> bool:
        return is_ai_admin_user(
            request.user
        )

    def has_add_permission(
        self,
        request: HttpRequest,
    ) -> bool:
        """
        Prevent manual creation that bypasses the audited AI request form.
        """

        return False

    def has_change_permission(
        self,
        request: HttpRequest,
        obj: AIAnalysis | None = None,
    ) -> bool:
        return is_ai_admin_user(
            request.user
        )

    def has_delete_permission(
        self,
        request: HttpRequest,
        obj: AIAnalysis | None = None,
    ) -> bool:
        """
        Disable hard deletion to protect forensic and audit history.
        """

        return False

    def save_model(
        self,
        request: HttpRequest,
        obj: AIAnalysis,
        form,
        change: bool,
    ) -> None:
        """
        Set creator when an administrator manually creates a record.
        """

        if not change and not obj.created_by_id:
            obj.created_by = request.user

        super().save_model(
            request,
            obj,
            form,
            change,
        )

    @admin.display(
        description="Evidence",
        ordering="evidence__evidence_title",
    )
    def evidence_reference(
        self,
        obj: AIAnalysis,
    ) -> str:
        return format_html(
            (
                '<strong>{}</strong><br>'
                '<span style="color:#64748b;">{}</span>'
            ),
            obj.evidence.evidence_title,
            obj.evidence.case.case_number,
        )

    @admin.display(
        description="Case",
    )
    def case_reference(
        self,
        obj: AIAnalysis,
    ) -> str:
        return (
            f"{obj.case.case_number} | "
            f"{obj.case.case_title}"
        )

    @admin.display(
        description="Analysis Type",
        ordering="analysis_type",
    )
    def analysis_type_badge(
        self,
        obj: AIAnalysis,
    ) -> str:
        return format_html(
            (
                '<span style="display:inline-flex;padding:4px 9px;'
                'border-radius:999px;background:#e0f2fe;'
                'color:#0369a1;font-weight:800;">{}</span>'
            ),
            obj.get_analysis_type_display(),
        )

    @admin.display(
        description="Status",
        ordering="status",
    )
    def status_badge(
        self,
        obj: AIAnalysis,
    ) -> str:
        color_map = {
            AIAnalysis.Status.PENDING: (
                "#fef3c7",
                "#92400e",
            ),
            AIAnalysis.Status.QUEUED: (
                "#e0e7ff",
                "#4338ca",
            ),
            AIAnalysis.Status.PROCESSING: (
                "#dbeafe",
                "#1d4ed8",
            ),
            AIAnalysis.Status.COMPLETED: (
                "#dcfce7",
                "#166534",
            ),
            AIAnalysis.Status.FAILED: (
                "#fee2e2",
                "#991b1b",
            ),
            AIAnalysis.Status.CANCELLED: (
                "#e2e8f0",
                "#475569",
            ),
        }

        background, color = color_map.get(
            obj.status,
            (
                "#e2e8f0",
                "#475569",
            ),
        )

        return format_html(
            (
                '<span style="display:inline-flex;padding:4px 9px;'
                'border-radius:999px;background:{};color:{};'
                'font-weight:800;">{}</span>'
            ),
            background,
            color,
            obj.get_status_display(),
        )

    @admin.display(
        description="Priority",
        ordering="priority",
    )
    def priority_badge(
        self,
        obj: AIAnalysis,
    ) -> str:
        color_map = {
            AIAnalysis.Priority.LOW: (
                "#dcfce7",
                "#166534",
            ),
            AIAnalysis.Priority.MEDIUM: (
                "#fef3c7",
                "#92400e",
            ),
            AIAnalysis.Priority.HIGH: (
                "#ffedd5",
                "#9a3412",
            ),
            AIAnalysis.Priority.CRITICAL: (
                "#fee2e2",
                "#991b1b",
            ),
        }

        background, color = color_map.get(
            obj.priority,
            (
                "#e2e8f0",
                "#475569",
            ),
        )

        return format_html(
            (
                '<span style="display:inline-flex;padding:4px 9px;'
                'border-radius:999px;background:{};color:{};'
                'font-weight:800;">{}</span>'
            ),
            background,
            color,
            obj.get_priority_display(),
        )

    @admin.display(
        description="Threat",
        ordering="threat_level",
    )
    def threat_badge(
        self,
        obj: AIAnalysis,
    ) -> str:
        color_map = {
            AIAnalysis.ThreatLevel.UNKNOWN: (
                "#e2e8f0",
                "#475569",
            ),
            AIAnalysis.ThreatLevel.NONE: (
                "#dcfce7",
                "#166534",
            ),
            AIAnalysis.ThreatLevel.LOW: (
                "#dbeafe",
                "#1d4ed8",
            ),
            AIAnalysis.ThreatLevel.MEDIUM: (
                "#fef3c7",
                "#92400e",
            ),
            AIAnalysis.ThreatLevel.HIGH: (
                "#ffedd5",
                "#9a3412",
            ),
            AIAnalysis.ThreatLevel.CRITICAL: (
                "#fee2e2",
                "#991b1b",
            ),
        }

        background, color = color_map.get(
            obj.threat_level,
            (
                "#e2e8f0",
                "#475569",
            ),
        )

        return format_html(
            (
                '<span style="display:inline-flex;padding:4px 9px;'
                'border-radius:999px;background:{};color:{};'
                'font-weight:800;">{}</span>'
            ),
            background,
            color,
            obj.get_threat_level_display(),
        )

    @admin.display(
        description="Risk",
        ordering="risk_score",
    )
    def risk_score_badge(
        self,
        obj: AIAnalysis,
    ) -> str:
        return format_score_badge(
            obj.risk_score,
            kind="risk",
        )

    @admin.display(
        description="Confidence",
        ordering="confidence_score",
    )
    def confidence_score_badge(
        self,
        obj: AIAnalysis,
    ) -> str:
        return format_score_badge(
            obj.confidence_score,
            kind="confidence",
        )

    @admin.display(
        description="Provider",
        ordering="provider",
    )
    def provider_display(
        self,
        obj: AIAnalysis,
    ) -> str:
        model_name = (
            obj.model_name
            or "Not recorded"
        )

        return format_html(
            (
                '<strong>{}</strong><br>'
                '<span style="color:#64748b;">{}</span>'
            ),
            obj.get_provider_display(),
            model_name,
        )

    @admin.display(
        description="Tokens",
        ordering="total_tokens",
    )
    def token_total(
        self,
        obj: AIAnalysis,
    ) -> str:
        return f"{obj.total_tokens:,}"

    @admin.display(
        description="Token Usage",
    )
    def token_usage_display(
        self,
        obj: AIAnalysis,
    ) -> str:
        return format_html(
            (
                '<div style="line-height:1.7;">'
                '<strong>Input:</strong> {:,}<br>'
                '<strong>Output:</strong> {:,}<br>'
                '<strong>Total:</strong> {:,}'
                '</div>'
            ),
            obj.input_tokens,
            obj.output_tokens,
            obj.total_tokens,
        )

    @admin.display(
        description="Cache",
        ordering="cache_status",
    )
    def cache_badge(
        self,
        obj: AIAnalysis,
    ) -> str:
        if obj.result_is_stale:
            return format_html(
                (
                    '<span style="display:inline-flex;padding:4px 9px;'
                    'border-radius:999px;background:#fee2e2;'
                    'color:#991b1b;font-weight:800;">Stale</span>'
                )
            )

        if obj.cached_result:
            return format_html(
                (
                    '<span style="display:inline-flex;padding:4px 9px;'
                    'border-radius:999px;background:#dcfce7;'
                    'color:#166534;font-weight:800;">Cached</span>'
                )
            )

        return format_html(
            (
                '<span style="display:inline-flex;padding:4px 9px;'
                'border-radius:999px;background:#e2e8f0;'
                'color:#475569;font-weight:800;">Fresh</span>'
            )
        )

    @admin.display(
        description="Created By",
        ordering="created_by__username",
    )
    def created_by_display(
        self,
        obj: AIAnalysis,
    ) -> str:
        return (
            obj.created_by.full_name
            or obj.created_by.username
        )

    @admin.display(
        description="Active",
        boolean=True,
        ordering="is_active",
    )
    def active_badge(
        self,
        obj: AIAnalysis,
    ) -> bool:
        return obj.is_active

    @admin.display(
        description="Current Evidence Hash",
    )
    def current_evidence_hash(
        self,
        obj: AIAnalysis,
    ) -> str:
        return (
            obj.evidence.sha256_hash
            or "Hash not available"
        )

    @admin.display(
        description="Result Stale",
        boolean=True,
    )
    def stale_result_display(
        self,
        obj: AIAnalysis,
    ) -> bool:
        return obj.result_is_stale

    @admin.display(
        description="Processing Duration",
    )
    def processing_duration_display(
        self,
        obj: AIAnalysis,
    ) -> str:
        duration = obj.processing_duration

        if duration is None:
            return "Not started"

        total_seconds = int(
            duration.total_seconds()
        )

        hours, remainder = divmod(
            total_seconds,
            3600,
        )

        minutes, seconds = divmod(
            remainder,
            60,
        )

        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @admin.action(
        description="Reset selected failed/cancelled analyses to Pending"
    )
    def mark_pending(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ) -> None:
        """
        Reset eligible records with an atomic compare-and-set transition.

        This does not depend on select_for_update(), so a concurrent lifecycle
        change cannot be silently overwritten on SQLite.
        """

        reset_count = 0
        skipped_count = 0

        for analysis_id in queryset.values_list(
            "pk",
            flat=True,
        ):
            analysis = (
                AIAnalysis.objects
                .select_related("evidence")
                .get(pk=analysis_id)
            )

            if (
                not analysis.is_active
                or not analysis.evidence.is_active
                or analysis.status not in {
                    AIAnalysis.Status.FAILED,
                    AIAnalysis.Status.CANCELLED,
                }
            ):
                skipped_count += 1
                continue

            previous_status = analysis.status
            previous_error = analysis.last_error
            previous_attempts = analysis.api_attempts
            observed_updated_date = analysis.updated_date
            transition_time = timezone.now()

            with transaction.atomic():
                updated_rows = (
                    AIAnalysis.objects
                    .filter(
                        pk=analysis.pk,
                        is_active=True,
                        evidence__is_active=True,
                        status=previous_status,
                        updated_date=observed_updated_date,
                    )
                    .update(
                        status=AIAnalysis.Status.PENDING,
                        started_at=None,
                        completed_at=None,
                        processing_time_seconds=None,
                        last_error="",
                        provider_error_code="",
                        quota_exceeded=False,
                        cached_result=False,
                        cache_status=AIAnalysis.CacheStatus.NOT_CACHED,
                        api_attempts=0,
                        updated_date=transition_time,
                    )
                )

                if updated_rows != 1:
                    skipped_count += 1
                    continue

                analysis.refresh_from_db()

                create_analysis_log(
                    analysis,
                    AIAnalysisLog.EventType.RETRY,
                    "Analysis reset to Pending from Django admin.",
                    actor=request.user,
                    metadata={
                        "previous_status": previous_status,
                        "previous_error": previous_error,
                        "previous_attempts": previous_attempts,
                        "admin_action": True,
                        "transition_strategy": "atomic_compare_and_set",
                    },
                )

            reset_count += 1

        self.message_user(
            request,
            (
                f"{reset_count} analysis record(s) reset to Pending; "
                f"{skipped_count} skipped."
            ),
            (
                messages.SUCCESS
                if reset_count
                else messages.WARNING
            ),
        )

    @admin.action(
        description="Cancel selected pending/queued analyses"
    )
    def mark_cancelled(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ) -> None:
        cancelled_count = 0
        skipped_count = 0

        for analysis_id in queryset.values_list(
            "pk",
            flat=True,
        ):
            analysis = AIAnalysis.objects.get(
                pk=analysis_id
            )

            try:
                cancel_analysis(
                    analysis,
                    actor=request.user,
                    reason=(
                        "Cancelled through the Django admin bulk action."
                    ),
                )
            except AIAnalysisStateError:
                skipped_count += 1
                continue

            cancelled_count += 1

        self.message_user(
            request,
            (
                f"{cancelled_count} analysis record(s) cancelled; "
                f"{skipped_count} skipped."
            ),
            (
                messages.SUCCESS
                if cancelled_count
                else messages.WARNING
            ),
        )

    @admin.action(
        description="Archive selected active analyses"
    )
    def archive_selected(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ) -> None:
        """
        Archive selected analyses without racing active AI execution.

        The service performs an atomic compare-and-set transition. Queued or
        processing analyses are intentionally skipped so an in-flight Gemini
        result cannot conflict with an archive operation.
        """

        archived_count = 0
        skipped_count = 0
        running_count = 0

        for analysis_id in queryset.values_list(
            "pk",
            flat=True,
        ):
            analysis = AIAnalysis.objects.get(
                pk=analysis_id
            )

            if not analysis.is_active:
                skipped_count += 1
                continue

            try:
                archived_analysis = archive_analysis(
                    analysis,
                    actor=request.user,
                    reason=(
                        "Archived through the Django admin bulk action."
                    ),
                )
            except AIAnalysisStateError:
                running_count += 1
                continue

            if archived_analysis.is_active:
                skipped_count += 1
                continue

            archived_count += 1

        summary_parts = [
            f"{archived_count} analysis record(s) archived",
        ]

        if running_count:
            summary_parts.append(
                (
                    f"{running_count} queued/processing record(s) "
                    "skipped for execution safety"
                )
            )

        if skipped_count:
            summary_parts.append(
                f"{skipped_count} other record(s) skipped"
            )

        self.message_user(
            request,
            "; ".join(summary_parts) + ".",
            (
                messages.SUCCESS
                if archived_count
                else messages.WARNING
            ),
        )

    @admin.action(
        description="Restore selected archived analyses"
    )
    def restore_selected(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ) -> None:
        restored_count = 0
        skipped_count = 0

        for analysis_id in queryset.values_list(
            "pk",
            flat=True,
        ):
            analysis = (
                AIAnalysis.objects
                .select_related("evidence")
                .get(pk=analysis_id)
            )

            if analysis.is_active:
                skipped_count += 1
                continue

            try:
                restore_analysis(
                    analysis,
                    actor=request.user,
                )
            except AIAnalysisStateError:
                skipped_count += 1
                continue

            restored_count += 1

        self.message_user(
            request,
            (
                f"{restored_count} analysis record(s) restored; "
                f"{skipped_count} skipped."
            ),
            (
                messages.SUCCESS
                if restored_count
                else messages.WARNING
            ),
        )

    @admin.action(
        description="Invalidate cache for selected analyses"
    )
    def invalidate_cache(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ) -> None:
        invalidated_count = 0
        skipped_count = 0

        for analysis_id in queryset.values_list(
            "pk",
            flat=True,
        ):
            analysis = AIAnalysis.objects.get(
                pk=analysis_id
            )

            # Do not race an active provider execution. Its completion write
            # owns the cache/result lifecycle for PROCESSING records.
            if analysis.status in {
                AIAnalysis.Status.QUEUED,
                AIAnalysis.Status.PROCESSING,
            }:
                skipped_count += 1
                continue

            observed_status = analysis.status
            observed_active = analysis.is_active
            observed_updated_date = analysis.updated_date
            transition_time = timezone.now()

            with transaction.atomic():
                updated_rows = (
                    AIAnalysis.objects
                    .filter(
                        pk=analysis.pk,
                        status=observed_status,
                        is_active=observed_active,
                        updated_date=observed_updated_date,
                    )
                    .update(
                        cached_result=False,
                        cache_status=AIAnalysis.CacheStatus.INVALIDATED,
                        updated_date=transition_time,
                    )
                )

                if updated_rows != 1:
                    skipped_count += 1
                    continue

                analysis.refresh_from_db()

                create_analysis_log(
                    analysis,
                    AIAnalysisLog.EventType.CACHE_INVALIDATED,
                    "Cache invalidated through the Django admin.",
                    actor=request.user,
                    metadata={
                        "admin_action": True,
                        "transition_strategy": "atomic_compare_and_set",
                    },
                )

            invalidated_count += 1

        self.message_user(
            request,
            (
                f"Cache invalidated for {invalidated_count} analysis "
                f"record(s); {skipped_count} skipped."
            ),
            (
                messages.SUCCESS
                if invalidated_count
                else messages.WARNING
            ),
        )

    @admin.action(
        description="Clear quota-exceeded flag"
    )
    def clear_quota_flag(
        self,
        request: HttpRequest,
        queryset: QuerySet,
    ) -> None:
        cleared_count = 0
        skipped_count = 0

        for analysis_id in queryset.values_list(
            "pk",
            flat=True,
        ):
            analysis = AIAnalysis.objects.get(
                pk=analysis_id
            )

            if not analysis.quota_exceeded:
                skipped_count += 1
                continue

            observed_status = analysis.status
            observed_active = analysis.is_active
            observed_updated_date = analysis.updated_date
            transition_time = timezone.now()

            with transaction.atomic():
                updated_rows = (
                    AIAnalysis.objects
                    .filter(
                        pk=analysis.pk,
                        status=observed_status,
                        is_active=observed_active,
                        quota_exceeded=True,
                        updated_date=observed_updated_date,
                    )
                    .update(
                        quota_exceeded=False,
                        provider_error_code="",
                        updated_date=transition_time,
                    )
                )

                if updated_rows != 1:
                    skipped_count += 1
                    continue

                analysis.refresh_from_db()

                create_analysis_log(
                    analysis,
                    AIAnalysisLog.EventType.NOTE,
                    "Quota-exceeded flag cleared through the Django admin.",
                    actor=request.user,
                    metadata={
                        "admin_action": True,
                        "transition_strategy": "atomic_compare_and_set",
                    },
                )

            cleared_count += 1

        self.message_user(
            request,
            (
                f"{cleared_count} quota flag(s) cleared; "
                f"{skipped_count} skipped."
            ),
            (
                messages.SUCCESS
                if cleared_count
                else messages.WARNING
            ),
        )



# ==========================================================
# AI Analysis Log Admin
# ==========================================================

@admin.register(AIAnalysisLog)
class AIAnalysisLogAdmin(admin.ModelAdmin):
    """
    Read-only administrative interface for AI analysis audit events.
    """

    list_display = (
        "created_date",
        "analysis_reference",
        "event_badge",
        "message_preview",
        "actor_display",
        "provider_display",
        "provider_request_id",
    )

    list_display_links = (
        "created_date",
        "analysis_reference",
    )

    list_filter = (
        "event_type",
        "provider",
        "created_date",
    )

    search_fields = (
        "analysis__analysis_number",
        "analysis__title",
        "analysis__evidence__evidence_title",
        "analysis__evidence__case__case_number",
        "message",
        "provider_request_id",
        "actor__username",
        "actor__full_name",
    )

    ordering = (
        "-created_date",
    )

    date_hierarchy = "created_date"

    list_per_page = 40

    show_full_result_count = False

    readonly_fields = (
        "id",
        "analysis",
        "event_type",
        "message",
        "metadata",
        "actor",
        "provider",
        "provider_request_id",
        "created_date",
    )

    fieldsets = (
        (
            "Event Identity",
            {
                "fields": (
                    "id",
                    "analysis",
                    "event_type",
                    "created_date",
                )
            },
        ),
        (
            "Event Detail",
            {
                "fields": (
                    "message",
                    "metadata",
                )
            },
        ),
        (
            "Actor and Provider",
            {
                "fields": (
                    "actor",
                    "provider",
                    "provider_request_id",
                )
            },
        ),
    )

    def get_queryset(
        self,
        request: HttpRequest,
    ) -> QuerySet:
        return (
            super()
            .get_queryset(
                request
            )
            .select_related(
                "analysis",
                "analysis__evidence",
                "analysis__evidence__case",
                "actor",
            )
        )

    def has_module_permission(
        self,
        request: HttpRequest,
    ) -> bool:
        return is_ai_admin_user(
            request.user
        )

    def has_view_permission(
        self,
        request: HttpRequest,
        obj: AIAnalysisLog | None = None,
    ) -> bool:
        return is_ai_admin_user(
            request.user
        )

    def has_add_permission(
        self,
        request: HttpRequest,
    ) -> bool:
        return False

    def has_change_permission(
        self,
        request: HttpRequest,
        obj: AIAnalysisLog | None = None,
    ) -> bool:
        return False

    def has_delete_permission(
        self,
        request: HttpRequest,
        obj: AIAnalysisLog | None = None,
    ) -> bool:
        return False

    @admin.display(
        description="Analysis",
        ordering="analysis__analysis_number",
    )
    def analysis_reference(
        self,
        obj: AIAnalysisLog,
    ) -> str:
        return format_html(
            (
                '<strong>{}</strong><br>'
                '<span style="color:#64748b;">{}</span>'
            ),
            obj.analysis.analysis_number,
            obj.analysis.title,
        )

    @admin.display(
        description="Event",
        ordering="event_type",
    )
    def event_badge(
        self,
        obj: AIAnalysisLog,
    ) -> str:
        color_map = {
            AIAnalysisLog.EventType.CREATED: (
                "#e0e7ff",
                "#4338ca",
            ),
            AIAnalysisLog.EventType.QUEUED: (
                "#dbeafe",
                "#1d4ed8",
            ),
            AIAnalysisLog.EventType.STARTED: (
                "#cffafe",
                "#155e75",
            ),
            AIAnalysisLog.EventType.PROVIDER_REQUEST: (
                "#ede9fe",
                "#6d28d9",
            ),
            AIAnalysisLog.EventType.PROVIDER_RESPONSE: (
                "#dcfce7",
                "#166534",
            ),
            AIAnalysisLog.EventType.RETRY: (
                "#fef3c7",
                "#92400e",
            ),
            AIAnalysisLog.EventType.COMPLETED: (
                "#dcfce7",
                "#166534",
            ),
            AIAnalysisLog.EventType.FAILED: (
                "#fee2e2",
                "#991b1b",
            ),
            AIAnalysisLog.EventType.CANCELLED: (
                "#e2e8f0",
                "#475569",
            ),
            AIAnalysisLog.EventType.REVIEWED: (
                "#ccfbf1",
                "#0f766e",
            ),
            AIAnalysisLog.EventType.CACHE_HIT: (
                "#dcfce7",
                "#166534",
            ),
            AIAnalysisLog.EventType.CACHE_INVALIDATED: (
                "#ffedd5",
                "#9a3412",
            ),
            AIAnalysisLog.EventType.ARCHIVED: (
                "#fee2e2",
                "#991b1b",
            ),
            AIAnalysisLog.EventType.RESTORED: (
                "#dcfce7",
                "#166534",
            ),
            AIAnalysisLog.EventType.NOTE: (
                "#e2e8f0",
                "#475569",
            ),
        }

        background, color = color_map.get(
            obj.event_type,
            (
                "#e2e8f0",
                "#475569",
            ),
        )

        return format_html(
            (
                '<span style="display:inline-flex;padding:4px 9px;'
                'border-radius:999px;background:{};color:{};'
                'font-weight:800;">{}</span>'
            ),
            background,
            color,
            obj.get_event_type_display(),
        )

    @admin.display(
        description="Message",
    )
    def message_preview(
        self,
        obj: AIAnalysisLog,
    ) -> str:
        message = obj.message

        if len(message) > 90:
            return f"{message[:90]}…"

        return message

    @admin.display(
        description="Actor",
        ordering="actor__username",
    )
    def actor_display(
        self,
        obj: AIAnalysisLog,
    ) -> str:
        if obj.actor is None:
            return "System"

        return (
            obj.actor.full_name
            or obj.actor.username
        )

    @admin.display(
        description="Provider",
        ordering="provider",
    )
    def provider_display(
        self,
        obj: AIAnalysisLog,
    ) -> str:
        if not obj.provider:
            return "—"

        return obj.get_provider_display()


# ==========================================================
# Admin Site Branding
# ==========================================================

admin.site.site_header = "AIDEX Administration"
admin.site.site_title = "AIDEX Admin"
admin.site.index_title = "AI Digital Evidence Intelligence System"