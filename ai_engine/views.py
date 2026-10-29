"""
AIDEX AI Engine Views
=====================

Professional role-aware workflows for AI-assisted forensic analysis.

Important execution rule
------------------------
Creating or opening an analysis never calls an AI provider automatically.

The selected provider is called only after an authenticated user submits the
Run Analysis action. During development, the request is executed
synchronously through ai_engine.services.execute_analysis(). For production,
move that service call to Celery, RQ or another background worker.
"""

from __future__ import annotations

import logging

from functools import wraps
from typing import Any, Callable

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Avg, F, Q, QuerySet, Sum
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import (
    require_GET,
    require_POST,
    require_http_methods,
)

from evidence.models import Evidence

from .forms import (
    PROMPT_CUSTOM,
    AIAnalysisArchiveForm,
    AIAnalysisCancelForm,
    AIAnalysisFilterForm,
    AIAnalysisReviewForm,
    AIAnalysisRunForm,
)
from .models import AIAnalysis, AIAnalysisLog
from .services import (
    AIServiceError,
    build_cache_key_from_values,
    execute_analysis,
    get_configured_model_name,
)

logger = logging.getLogger(__name__)



# ============================================================================
# Role Configuration
# ============================================================================

ROLE_ADMINISTRATOR = "ADMINISTRATOR"
ROLE_INVESTIGATOR = "INVESTIGATOR"
ROLE_CYBER_OFFICER = "CYBER_OFFICER"

ROLE_ALIASES = {
    "ADMIN": ROLE_ADMINISTRATOR,
    "ADMINISTRATOR": ROLE_ADMINISTRATOR,
    "SUPERADMIN": ROLE_ADMINISTRATOR,
    "SUPER_ADMIN": ROLE_ADMINISTRATOR,
    "INVESTIGATOR": ROLE_INVESTIGATOR,
    "CYBEROFFICER": ROLE_CYBER_OFFICER,
    "CYBER_OFFICER": ROLE_CYBER_OFFICER,
    "CYBER OFFICER": ROLE_CYBER_OFFICER,
    "OFFICER": ROLE_CYBER_OFFICER,
}


# ============================================================================
# Role and Permission Utilities
# ============================================================================

def normalize_role(role_value: Any) -> str:
    normalized_role = (
        str(role_value or "")
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return ROLE_ALIASES.get(normalized_role, normalized_role)


def get_user_role(user: Any) -> str:
    if getattr(user, "is_superuser", False):
        return ROLE_ADMINISTRATOR

    return normalize_role(getattr(user, "role", ""))


def user_has_role(user: Any, *roles: str) -> bool:
    allowed_roles = {
        normalize_role(role)
        for role in roles
    }

    return get_user_role(user) in allowed_roles


def ai_role_required(*allowed_roles: str) -> Callable:
    normalized_roles = {
        normalize_role(role)
        for role in allowed_roles
    }

    def decorator(view_function: Callable) -> Callable:
        @wraps(view_function)
        @login_required
        def wrapper(
            request: HttpRequest,
            *args: Any,
            **kwargs: Any,
        ) -> HttpResponse:
            if get_user_role(request.user) not in normalized_roles:
                raise PermissionDenied(
                    "You do not have permission to perform this action."
                )

            return view_function(request, *args, **kwargs)

        return wrapper

    return decorator


def can_create_analysis(user: Any) -> bool:
    return user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_INVESTIGATOR,
        ROLE_CYBER_OFFICER,
    )


def can_run_analysis(
    user: Any,
    analysis: AIAnalysis,
) -> bool:
    if not analysis.is_active:
        return False

    if not analysis.evidence.is_active:
        return False

    if analysis.status != AIAnalysis.Status.PENDING:
        return False

    if user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return True

    return (
        user_has_role(user, ROLE_INVESTIGATOR)
        and analysis.created_by_id == user.pk
    )


def can_cancel_analysis(
    user: Any,
    analysis: AIAnalysis,
) -> bool:
    if not analysis.is_active:
        return False

    if analysis.status not in {
        AIAnalysis.Status.PENDING,
        AIAnalysis.Status.QUEUED,
    }:
        return False

    if user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return True

    return (
        user_has_role(user, ROLE_INVESTIGATOR)
        and analysis.created_by_id == user.pk
    )


def can_retry_analysis(
    user: Any,
    analysis: AIAnalysis,
) -> bool:
    if not analysis.can_retry:
        return False

    if user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return True

    return (
        user_has_role(user, ROLE_INVESTIGATOR)
        and analysis.created_by_id == user.pk
    )


def can_review_analysis(
    user: Any,
    analysis: AIAnalysis | None = None,
) -> bool:
    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    if analysis is None:
        return True

    return (
        analysis.is_active
        and analysis.status in {
            AIAnalysis.Status.COMPLETED,
            AIAnalysis.Status.FAILED,
        }
    )


def can_archive_analysis(
    user: Any,
    analysis: AIAnalysis | None = None,
) -> bool:
    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    if analysis is None:
        return True

    # Never archive a record while an execution is queued or in progress.
    # This avoids conflicting lifecycle writes with Run/worker execution.
    return (
        analysis.is_active
        and analysis.status not in {
            AIAnalysis.Status.QUEUED,
            AIAnalysis.Status.PROCESSING,
        }
    )


def can_restore_analysis(
    user: Any,
    analysis: AIAnalysis | None = None,
) -> bool:
    """
    Return whether the user may restore an archived AI analysis.
    """

    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    if analysis is None:
        return True

    return bool(
        not analysis.is_active
        and analysis.evidence.is_active
    )


def can_view_usage(user: Any) -> bool:
    return user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    )


# ============================================================================
# Queryset and Object Utilities
# ============================================================================

def get_accessible_analysis_queryset(
    user: Any,
) -> QuerySet[AIAnalysis]:
    queryset = AIAnalysis.objects.select_related(
        "evidence",
        "evidence__case",
        "evidence__uploaded_by",
        "evidence__verified_by",
        "evidence__case__created_by",
        "evidence__case__assigned_investigator",
        "created_by",
        "reviewed_by",
    )

    if not getattr(user, "is_authenticated", False):
        return queryset.none()

    role = get_user_role(user)

    if role in {
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    }:
        return queryset

    if role == ROLE_INVESTIGATOR:
        return (
            queryset
            .filter(
                Q(created_by=user)
                | Q(evidence__uploaded_by=user)
                | Q(evidence__case__created_by=user)
                | Q(evidence__case__assigned_investigator=user)
            )
            .distinct()
        )

    return queryset.none()


def get_accessible_analysis_or_404(
    user: Any,
    analysis_id: Any,
) -> AIAnalysis:
    return get_object_or_404(
        get_accessible_analysis_queryset(user),
        pk=analysis_id,
    )


# ============================================================================
# Logging and State Utilities
# ============================================================================

def create_analysis_log(
    analysis: AIAnalysis,
    event_type: str,
    message: str,
    actor: Any = None,
    metadata: dict[str, Any] | None = None,
) -> AIAnalysisLog:
    return AIAnalysisLog.objects.create(
        analysis=analysis,
        event_type=event_type,
        message=message.strip(),
        actor=(
            actor
            if getattr(actor, "is_authenticated", False)
            else None
        ),
        provider=analysis.provider,
        metadata=metadata or {},
    )


def build_query_string(request: HttpRequest) -> str:
    query_parameters = request.GET.copy()
    query_parameters.pop("page", None)
    return query_parameters.urlencode()


REVIEW_VERSION_SALT = "ai_engine.analysis_review.version"


def build_review_version_token(
    analysis: AIAnalysis,
) -> str:
    """
    Build a signed optimistic-lock token for the Human Review page.

    The token represents the exact AIAnalysis version shown to the reviewer.
    If another reviewer changes the record before this form is submitted,
    the stale form is rejected instead of silently overwriting newer review
    information.
    """

    return signing.dumps(
        {
            "analysis_id": str(analysis.pk),
            "updated_date": (
                analysis.updated_date.isoformat()
                if analysis.updated_date
                else ""
            ),
            "reviewed_at": (
                analysis.reviewed_at.isoformat()
                if analysis.reviewed_at
                else ""
            ),
            "reviewed_by_id": (
                str(analysis.reviewed_by_id)
                if analysis.reviewed_by_id
                else ""
            ),
        },
        salt=REVIEW_VERSION_SALT,
        compress=True,
    )


def review_version_matches(
    analysis: AIAnalysis,
    token: str,
) -> bool:
    """
    Return True only when a signed Human Review token still represents the
    current database version of the analysis.
    """

    if not token:
        return False

    try:
        payload = signing.loads(
            token,
            salt=REVIEW_VERSION_SALT,
        )
    except signing.BadSignature:
        return False

    return (
        payload.get("analysis_id") == str(analysis.pk)
        and payload.get("updated_date")
        == (
            analysis.updated_date.isoformat()
            if analysis.updated_date
            else ""
        )
        and payload.get("reviewed_at")
        == (
            analysis.reviewed_at.isoformat()
            if analysis.reviewed_at
            else ""
        )
        and payload.get("reviewed_by_id")
        == (
            str(analysis.reviewed_by_id)
            if analysis.reviewed_by_id
            else ""
        )
    )


def get_execution_cache_preferences(
    analysis: AIAnalysis,
) -> tuple[bool, bool]:
    """
    Return (allow_cache, force_reanalysis) for an analysis.

    AIAnalysisRunForm contains request-only cache controls, so their values
    are stored in the CREATED audit-log metadata when the analysis record is
    created. This preserves the user's execution intent across the redirect
    from Create Analysis -> Analysis Detail -> Run Analysis without adding a
    database field solely for a UI execution preference.

    Older analysis records created before this behavior existed fall back to
    the previous safe behavior: cache reuse allowed and force disabled.
    """
    created_log = (
        analysis.logs
        .filter(
            event_type=AIAnalysisLog.EventType.CREATED,
        )
        .order_by("-created_date")
        .first()
    )

    if created_log is None:
        return True, False

    metadata = created_log.metadata or {}

    force_reanalysis = bool(
        metadata.get(
            "force_reanalysis_requested",
            False,
        )
    )

    if "use_cached_result_requested" in metadata:
        allow_cache = bool(
            metadata.get(
                "use_cached_result_requested",
                False,
            )
        )
    else:
        # Backward compatibility for analyses created before this fix.
        allow_cache = True

    if force_reanalysis:
        allow_cache = False

    return allow_cache, force_reanalysis


def get_daily_user_queue_count(user: Any) -> int:
    today = timezone.localdate()

    return AIAnalysisLog.objects.filter(
        actor=user,
        event_type=AIAnalysisLog.EventType.QUEUED,
        created_date__date=today,
    ).count()


def check_configured_daily_limit(
    user: Any,
) -> tuple[bool, int, int]:
    configured_limit = int(
        getattr(
            settings,
            "AIDEX_AI_DAILY_USER_LIMIT",
            0,
        )
        or 0
    )

    current_count = get_daily_user_queue_count(user)

    if configured_limit <= 0:
        return True, current_count, configured_limit

    return (
        current_count < configured_limit,
        current_count,
        configured_limit,
    )


def get_matching_cached_analysis(
    form: AIAnalysisRunForm,
) -> AIAnalysis | None:
    evidence = form.cleaned_data["evidence"]
    analysis_type = form.cleaned_data["analysis_type"]
    prompt_version = form.cleaned_data["prompt_version"]
    prompt_template = form.cleaned_data["prompt_template"]
    custom_prompt = form.cleaned_data.get("custom_prompt", "")
    provider = form.cleaned_data["provider"]

    request_prompt = (
        custom_prompt
        if prompt_template == PROMPT_CUSTOM
        else prompt_template
    )

    expected_cache_key = build_cache_key_from_values(
        evidence_hash=evidence.sha256_hash,
        analysis_type=analysis_type,
        prompt_version=prompt_version,
        request_prompt=request_prompt,
        provider=provider,
        model_name=get_configured_model_name(provider),
    )

    current_model_name = get_configured_model_name(provider)

    return (
        get_accessible_analysis_queryset(form.current_user)
        .filter(
            evidence=evidence,
            analysis_type=analysis_type,
            prompt_version=prompt_version,
            request_prompt=request_prompt,
            provider=provider,
            model_name=current_model_name,
            evidence_hash_at_analysis=evidence.sha256_hash,
            cache_key=expected_cache_key,
            status=AIAnalysis.Status.COMPLETED,
            is_active=True,
        )
        .order_by("-completed_at", "-created_date")
        .first()
    )


# ============================================================================
# Filtering and Statistics
# ============================================================================

def apply_analysis_filters(
    queryset: QuerySet[AIAnalysis],
    filter_form: AIAnalysisFilterForm,
) -> QuerySet[AIAnalysis]:
    if not filter_form.is_valid():
        return queryset.order_by("-created_date")

    cleaned_data = filter_form.cleaned_data

    search_value = (
        cleaned_data.get("search", "")
        or ""
    ).strip()

    case = cleaned_data.get("case")
    evidence = cleaned_data.get("evidence")
    analysis_type = cleaned_data.get("analysis_type")
    status = cleaned_data.get("status")
    priority = cleaned_data.get("priority")
    threat_level = cleaned_data.get("threat_level")
    provider = cleaned_data.get("provider")
    created_by = cleaned_data.get("created_by")
    date_from = cleaned_data.get("date_from")
    date_to = cleaned_data.get("date_to")
    minimum_confidence = cleaned_data.get("minimum_confidence")
    minimum_risk = cleaned_data.get("minimum_risk")
    cache_state = cleaned_data.get("cache_state")
    active_state = cleaned_data.get("active_state")
    ordering = (
        cleaned_data.get("ordering")
        or "-created_date"
    )

    if search_value:
        queryset = queryset.filter(
            Q(analysis_number__icontains=search_value)
            | Q(title__icontains=search_value)
            | Q(ai_summary__icontains=search_value)
            | Q(evidence__evidence_title__icontains=search_value)
            | Q(evidence__original_filename__icontains=search_value)
            | Q(evidence__case__case_number__icontains=search_value)
            | Q(evidence__case__case_title__icontains=search_value)
            | Q(created_by__username__icontains=search_value)
            | Q(created_by__full_name__icontains=search_value)
        )

    if case:
        queryset = queryset.filter(evidence__case=case)

    if evidence:
        queryset = queryset.filter(evidence=evidence)

    if analysis_type:
        queryset = queryset.filter(analysis_type=analysis_type)

    if status:
        queryset = queryset.filter(status=status)

    if priority:
        queryset = queryset.filter(priority=priority)

    if threat_level:
        queryset = queryset.filter(threat_level=threat_level)

    if provider:
        queryset = queryset.filter(provider=provider)

    if created_by:
        queryset = queryset.filter(created_by=created_by)

    if date_from:
        queryset = queryset.filter(
            created_date__date__gte=date_from
        )

    if date_to:
        queryset = queryset.filter(
            created_date__date__lte=date_to
        )

    if minimum_confidence is not None:
        queryset = queryset.filter(
            confidence_score__gte=minimum_confidence
        )

    if minimum_risk is not None:
        queryset = queryset.filter(
            risk_score__gte=minimum_risk
        )

    if cache_state == "cached":
        queryset = queryset.filter(cached_result=True)

    elif cache_state == "fresh":
        queryset = queryset.filter(cached_result=False)

    elif cache_state == "stale":
        queryset = (
            queryset
            .exclude(evidence_hash_at_analysis="")
            .exclude(evidence__sha256_hash="")
            .exclude(
                evidence_hash_at_analysis=F(
                    "evidence__sha256_hash"
                )
            )
        )

    if active_state == "active":
        queryset = queryset.filter(is_active=True)

    elif active_state == "inactive":
        queryset = queryset.filter(is_active=False)

    allowed_ordering = {
        "-created_date",
        "created_date",
        "title",
        "-title",
        "-risk_score",
        "-confidence_score",
        "status",
        "priority",
    }

    if ordering not in allowed_ordering:
        ordering = "-created_date"

    return queryset.order_by(ordering)


def get_analysis_statistics(
    queryset: QuerySet[AIAnalysis],
) -> dict[str, Any]:
    aggregate_values = queryset.aggregate(
        total_input_tokens=Sum("input_tokens"),
        total_output_tokens=Sum("output_tokens"),
        total_tokens_used=Sum("total_tokens"),
        average_confidence=Avg("confidence_score"),
        average_risk=Avg("risk_score"),
    )

    return {
        "total_analyses": queryset.count(),
        "active_analyses": queryset.filter(
            is_active=True
        ).count(),
        "pending_analyses": queryset.filter(
            status__in={
                AIAnalysis.Status.PENDING,
                AIAnalysis.Status.QUEUED,
            },
            is_active=True,
        ).count(),
        "processing_analyses": queryset.filter(
            status=AIAnalysis.Status.PROCESSING,
            is_active=True,
        ).count(),
        "completed_analyses": queryset.filter(
            status=AIAnalysis.Status.COMPLETED,
            is_active=True,
        ).count(),
        "failed_analyses": queryset.filter(
            status=AIAnalysis.Status.FAILED,
        ).count(),
        "high_risk_analyses": queryset.filter(
            risk_score__gte=60,
            is_active=True,
        ).count(),
        "cached_analyses": queryset.filter(
            cached_result=True,
            is_active=True,
        ).count(),
        "archived_analyses": queryset.filter(
            is_active=False
        ).count(),
        "total_input_tokens": (
            aggregate_values["total_input_tokens"]
            or 0
        ),
        "total_output_tokens": (
            aggregate_values["total_output_tokens"]
            or 0
        ),
        "total_tokens_used": (
            aggregate_values["total_tokens_used"]
            or 0
        ),
        "average_confidence": (
            aggregate_values["average_confidence"]
            or 0
        ),
        "average_risk": (
            aggregate_values["average_risk"]
            or 0
        ),
    }


def get_common_context(
    request: HttpRequest,
) -> dict[str, Any]:
    return {
        "current_user": request.user,
        "current_role": get_user_role(request.user),
        "can_create_analysis": can_create_analysis(
            request.user
        ),
        "can_review_analysis": can_review_analysis(
            request.user
        ),
        "can_archive_analysis": can_archive_analysis(
            request.user
        ),
        "can_restore_analysis": can_restore_analysis(
            request.user
        ),
        "can_view_usage": can_view_usage(
            request.user
        ),
    }


# ============================================================================
# AI Engine Home and Dashboard
# ============================================================================

@login_required
@require_GET
def analysis_home(
    request: HttpRequest,
) -> HttpResponse:
    return redirect("ai_engine:analysis_list")


@login_required
@require_GET
def ai_dashboard(
    request: HttpRequest,
) -> HttpResponse:
    accessible_analyses = get_accessible_analysis_queryset(
        request.user
    )

    statistics = get_analysis_statistics(
        accessible_analyses
    )

    recent_analyses = (
        accessible_analyses
        .select_related(
            "evidence",
            "evidence__case",
            "created_by",
        )
        .order_by("-created_date")[:8]
    )

    recent_logs = (
        AIAnalysisLog.objects
        .filter(analysis__in=accessible_analyses)
        .select_related("analysis", "actor")
        .order_by("-created_date")[:8]
    )

    daily_queue_count = get_daily_user_queue_count(
        request.user
    )

    daily_user_limit = int(
        getattr(
            settings,
            "AIDEX_AI_DAILY_USER_LIMIT",
            0,
        )
        or 0
    )

    if daily_user_limit > 0:
        daily_usage_percentage = min(
            round(
                (
                    daily_queue_count
                    / daily_user_limit
                )
                * 100
            ),
            100,
        )
    else:
        daily_usage_percentage = 0

    context = get_common_context(request)

    context.update({
        "page_title": "AI Engine Dashboard",
        "provider_name": getattr(
            settings,
            "AI_PROVIDER",
            "GEMINI",
        ),
        "model_name": get_configured_model_name(),
        "ocr_available": bool(
            getattr(settings, "ENABLE_OCR", True)
        ),
        "recent_analyses": recent_analyses,
        "recent_logs": recent_logs,
        "daily_queue_count": daily_queue_count,
        "daily_user_limit": (
            daily_user_limit
            if daily_user_limit > 0
            else "∞"
        ),
        "daily_usage_percentage": daily_usage_percentage,
        **statistics,
    })

    return render(
        request,
        "ai_engine/dashboard.html",
        context,
    )


# ============================================================================
# Analysis List
# ============================================================================

@login_required
@require_GET
def analysis_list(
    request: HttpRequest,
) -> HttpResponse:
    accessible_analyses = get_accessible_analysis_queryset(
        request.user
    )

    filter_form = AIAnalysisFilterForm(
        request.GET or None,
        current_user=request.user,
    )

    filtered_analyses = apply_analysis_filters(
        queryset=accessible_analyses,
        filter_form=filter_form,
    )

    paginator = Paginator(filtered_analyses, 12)

    page_object = paginator.get_page(
        request.GET.get("page")
    )

    context = get_common_context(request)

    context.update({
        "page_title": "AI Analysis Management",
        "page_subtitle": (
            "Create, execute, review and monitor "
            "AI-assisted forensic analyses."
        ),
        "filter_form": filter_form,
        "analyses": page_object,
        "page_obj": page_object,
        "paginator": paginator,
        "query_string": build_query_string(request),
        "result_count": filtered_analyses.count(),
        **get_analysis_statistics(accessible_analyses),
    })

    return render(
        request,
        "ai_engine/analysis_list.html",
        context,
    )


# ============================================================================
# Analysis Creation
# ============================================================================

@ai_role_required(
    ROLE_ADMINISTRATOR,
    ROLE_INVESTIGATOR,
    ROLE_CYBER_OFFICER,
)
@require_http_methods(["GET", "POST"])
def analysis_create(
    request: HttpRequest,
) -> HttpResponse:
    if not can_create_analysis(request.user):
        raise PermissionDenied(
            "You do not have permission to create AI analyses."
        )

    if request.method == "POST":
        form = AIAnalysisRunForm(
            request.POST,
            current_user=request.user,
        )

        if form.is_valid():
            use_cached_result = form.cleaned_data.get(
                "use_cached_result",
                False,
            )

            force_reanalysis = form.cleaned_data.get(
                "force_reanalysis",
                False,
            )

            if use_cached_result and not force_reanalysis:
                cached_analysis = get_matching_cached_analysis(
                    form
                )

                if cached_analysis is not None:
                    messages.info(
                        request,
                        (
                            "A matching completed analysis already exists. "
                            "The cached result was reused without a new "
                            "provider request."
                        ),
                    )

                    create_analysis_log(
                        analysis=cached_analysis,
                        event_type=(
                            AIAnalysisLog.EventType.CACHE_HIT
                        ),
                        message=(
                            "Matching cached analysis result reused."
                        ),
                        actor=request.user,
                        metadata={
                            "reused_from_create_form": True,
                        },
                    )

                    return redirect(
                        "ai_engine:analysis_detail",
                        analysis_id=cached_analysis.pk,
                    )

            with transaction.atomic():
                analysis = form.save()

                create_analysis_log(
                    analysis=analysis,
                    event_type=AIAnalysisLog.EventType.CREATED,
                    message="AI analysis request created.",
                    actor=request.user,
                    metadata={
                        "analysis_type": analysis.analysis_type,
                        "prompt_version": analysis.prompt_version,
                        "evidence_id": str(
                            analysis.evidence_id
                        ),
                        "use_cached_result_requested": bool(
                            use_cached_result
                        ),
                        "force_reanalysis_requested": bool(
                            force_reanalysis
                        ),
                    },
                )

            messages.success(
                request,
                (
                    f"Analysis '{analysis.title}' was created for "
                    f"{analysis.get_provider_display()}. Use Run Analysis "
                    "to explicitly call the selected provider."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

    else:
        initial_data: dict[str, Any] = {}
        evidence_id = request.GET.get("evidence")

        if evidence_id:
            accessible_evidence = (
                AIAnalysisRunForm(
                    current_user=request.user
                )
                .fields["evidence"]
                .queryset
                .filter(pk=evidence_id)
                .first()
            )

            if accessible_evidence is not None:
                initial_data["evidence"] = accessible_evidence
                initial_data["title"] = (
                    "AI Analysis - "
                    f"{accessible_evidence.evidence_title}"
                )

        form = AIAnalysisRunForm(
            current_user=request.user,
            initial=initial_data,
        )

    context = get_common_context(request)

    context.update({
        "page_title": "Create AI Analysis",
        "page_subtitle": (
            "Prepare a forensic AI request without consuming provider "
            "quota until you explicitly run it."
        ),
        "form": form,
        "submit_label": "Create Analysis",
    })

    return render(
        request,
        "ai_engine/analysis_create.html",
        context,
    )


# ============================================================================
# Analysis Detail
# ============================================================================

@login_required
@require_GET
def analysis_detail(
    request: HttpRequest,
    analysis_id: Any,
) -> HttpResponse:
    analysis = get_accessible_analysis_or_404(
        user=request.user,
        analysis_id=analysis_id,
    )

    logs = (
        analysis.logs
        .select_related("actor")
        .order_by("-created_date")[:50]
    )

    context = get_common_context(request)

    context.update({
        "page_title": analysis.title,
        "page_subtitle": analysis.analysis_number,
        "analysis": analysis,
        "logs": logs,
        "can_run_this_analysis": can_run_analysis(
            request.user,
            analysis,
        ),
        "can_cancel_this_analysis": can_cancel_analysis(
            request.user,
            analysis,
        ),
        "can_retry_this_analysis": can_retry_analysis(
            request.user,
            analysis,
        ),
        "can_review_this_analysis": can_review_analysis(
            request.user,
            analysis,
        ),
        "can_archive_this_analysis": can_archive_analysis(
            request.user,
            analysis,
        ),
        "can_restore_this_analysis": can_restore_analysis(
            request.user,
            analysis,
        ),
    })

    return render(
        request,
        "ai_engine/analysis_detail.html",
        context,
    )


# ============================================================================
# Explicit Provider Execution
# ============================================================================

@login_required
@require_POST
def analysis_run(
    request: HttpRequest,
    analysis_id: Any,
) -> HttpResponse:
    """
    Queue and immediately execute one analysis through its selected provider.

    This synchronous implementation is appropriate for development and
    demonstrations. Use a background worker in production.

    The target analysis row is locked before changing its status so that
    simultaneous Run Analysis requests cannot execute the same record twice.
    """

    allowed_by_limit, current_count, configured_limit = (
        check_configured_daily_limit(
            request.user
        )
    )

    if not allowed_by_limit:
        messages.error(
            request,
            (
                "The configured daily AI request limit has been reached "
                f"({current_count}/{configured_limit}). Try again later "
                "or contact an administrator."
            ),
        )

        return redirect(
            "ai_engine:analysis_detail",
            analysis_id=analysis_id,
        )

    with transaction.atomic():
        # First resolve the requested analysis so we know which evidence row
        # should coordinate this Run operation.
        analysis = get_object_or_404(
            get_accessible_analysis_queryset(
                request.user
            ),
            pk=analysis_id,
        )

        # DB-backed per-evidence mutex:
        #
        # select_for_update() is ignored by SQLite. A no-op UPDATE, however,
        # still acquires the database write lock on SQLite and a row write
        # lock on databases such as PostgreSQL. Because every matching AI
        # analysis points to the same Evidence row, concurrent Run requests
        # for that evidence are serialized before the duplicate check.
        mutex_updated = (
            Evidence.objects
            .filter(pk=analysis.evidence_id)
            .update(
                updated_date=F("updated_date")
            )
        )

        if mutex_updated != 1:
            messages.error(
                request,
                "The evidence record could not be locked for analysis.",
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        # Re-read after acquiring the shared evidence mutex so all lifecycle
        # and duplicate checks use the latest committed state.
        analysis = get_object_or_404(
            get_accessible_analysis_queryset(
                request.user
            )
            .select_for_update(),
            pk=analysis_id,
        )

        if not can_run_analysis(
            request.user,
            analysis,
        ):
            if analysis.status in {
                AIAnalysis.Status.QUEUED,
                AIAnalysis.Status.PROCESSING,
                AIAnalysis.Status.COMPLETED,
            }:
                messages.warning(
                    request,
                    (
                        "This analysis has already been queued, is currently "
                        "processing, or has already been completed."
                    ),
                )

                return redirect(
                    "ai_engine:analysis_detail",
                    analysis_id=analysis.pk,
                )

            raise PermissionDenied(
                "You do not have permission to run this analysis."
            )

        duplicate_processing = (
            get_accessible_analysis_queryset(
                request.user
            )
            .select_for_update()
            .filter(
                evidence=analysis.evidence,
                analysis_type=analysis.analysis_type,
                prompt_version=analysis.prompt_version,
                request_prompt=analysis.request_prompt,
                provider=analysis.provider,
                evidence_hash_at_analysis=(
                    analysis.evidence.sha256_hash
                ),
                status__in={
                    AIAnalysis.Status.QUEUED,
                    AIAnalysis.Status.PROCESSING,
                },
                is_active=True,
            )
            .exclude(
                pk=analysis.pk
            )
            .exists()
        )

        if duplicate_processing:
            messages.warning(
                request,
                (
                    "An identical analysis request is already queued or processing "
                    "for this evidence and prompt."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        (
            allow_cache_for_execution,
            force_reanalysis_for_execution,
        ) = get_execution_cache_preferences(
            analysis
        )

        analysis.status = AIAnalysis.Status.QUEUED
        analysis.last_error = ""
        analysis.provider_error_code = ""
        analysis.quota_exceeded = False
        analysis.started_at = None
        analysis.completed_at = None
        analysis.processing_time_seconds = None

        analysis.save(
            update_fields=[
                "status",
                "last_error",
                "provider_error_code",
                "quota_exceeded",
                "started_at",
                "completed_at",
                "processing_time_seconds",
                "updated_date",
            ]
        )

        create_analysis_log(
            analysis=analysis,
            event_type=AIAnalysisLog.EventType.QUEUED,
            message="Analysis explicitly queued by the user.",
            actor=request.user,
            metadata={
                "daily_queue_count_before": current_count,
                "configured_daily_limit": configured_limit,
                "execution_mode": "synchronous_development",
                "provider": analysis.provider,
                "model_name": get_configured_model_name(
                    analysis.provider
                ),
                "allow_cache": allow_cache_for_execution,
                "force_reanalysis": (
                    force_reanalysis_for_execution
                ),
                "evidence_mutex_applied": True,
            },
        )

    try:
        outcome = execute_analysis(
            analysis,
            actor=request.user,
            allow_cache=allow_cache_for_execution,
            force=force_reanalysis_for_execution,
        )

    except AIServiceError:
        logger.exception(
            "AI service error while executing analysis %s.",
            analysis.pk,
        )

        messages.error(
            request,
            (
                "AI analysis could not be executed. "
                "Please review the analysis audit log or contact an "
                "administrator if the problem continues."
            ),
        )

        return redirect(
            "ai_engine:analysis_detail",
            analysis_id=analysis.pk,
        )

    except Exception:
        logger.exception(
            "Unexpected error while executing analysis %s.",
            analysis.pk,
        )

        messages.error(
            request,
            (
                "An unexpected error occurred while running the analysis. "
                "Technical details were recorded securely for review."
            ),
        )

        return redirect(
            "ai_engine:analysis_detail",
            analysis_id=analysis.pk,
        )

    if outcome.completed and outcome.cached:
        messages.info(
            request,
            (
                "A matching completed result was reused from cache. "
                "No provider quota was consumed."
            ),
        )

    elif outcome.completed:
        # Use the locked analysis record instead of assuming every execution
        # result (including test doubles) exposes an ``analysis`` attribute.
        provider_label = analysis.get_provider_display()
        messages.success(
            request,
            (
                f"{provider_label} analysis completed successfully. "
                "The forensic result has been saved."
            ),
        )

    else:
        provider_label = analysis.get_provider_display()
        logger.warning(
            "%s analysis failed for analysis %s. "
            "Review the persisted analysis error and audit log for details.",
            provider_label,
            analysis.pk,
        )

        messages.error(
            request,
            (
                f"{provider_label} analysis failed. "
                "Review the audit log for details or contact an "
                "administrator if the problem continues."
            ),
        )

    return redirect(
        "ai_engine:analysis_detail",
        analysis_id=analysis.pk,
    )


# ============================================================================
# Retry Failed Analysis
# ============================================================================

@login_required
@require_POST
def analysis_retry(
    request: HttpRequest,
    analysis_id: Any,
) -> HttpResponse:
    """
    Reset a retryable failed analysis to Pending using an atomic
    compare-and-set transition.

    QuerySet.update() performs the state change as one database write. This
    remains concurrency-safe on SQLite, where select_for_update() is ignored.
    """

    analysis = get_accessible_analysis_or_404(
        user=request.user,
        analysis_id=analysis_id,
    )

    if not can_retry_analysis(
        request.user,
        analysis,
    ):
        if analysis.status != AIAnalysis.Status.FAILED:
            messages.warning(
                request,
                "This analysis is no longer in a retryable failed state.",
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        raise PermissionDenied(
            "You do not have permission to retry this analysis."
        )

    previous_attempts = analysis.api_attempts
    previous_error = analysis.last_error
    transition_time = timezone.now()

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                status=AIAnalysis.Status.FAILED,
                is_active=True,
                quota_exceeded=False,
                api_attempts=previous_attempts,
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
            current = get_accessible_analysis_or_404(
                user=request.user,
                analysis_id=analysis.pk,
            )

            messages.warning(
                request,
                (
                    "This analysis changed while the retry request was being "
                    "processed. Refresh the page and try again if it is still "
                    "retryable."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=current.pk,
            )

        analysis.refresh_from_db()

        create_analysis_log(
            analysis=analysis,
            event_type=AIAnalysisLog.EventType.RETRY,
            message=(
                "Failed analysis reset for another explicit run."
            ),
            actor=request.user,
            metadata={
                "previous_attempts": previous_attempts,
                "previous_error": previous_error,
                "transition_strategy": "atomic_compare_and_set",
            },
        )

    messages.success(
        request,
        (
            "The failed analysis was reset. "
            "Use Run Analysis to execute it again."
        ),
    )

    return redirect(
        "ai_engine:analysis_detail",
        analysis_id=analysis.pk,
    )


# ============================================================================
# Cancel Analysis
# ============================================================================

@login_required
@require_http_methods(["GET", "POST"])
def analysis_cancel(
    request: HttpRequest,
    analysis_id: Any,
) -> HttpResponse:
    """
    Cancel a pending or queued analysis with an atomic compare-and-set
    transition.

    The UPDATE requires the status to still equal the status observed before
    the request. If Run/worker execution changes the lifecycle first, the
    cancellation safely loses the race instead of overwriting that state.
    """

    analysis = get_accessible_analysis_or_404(
        user=request.user,
        analysis_id=analysis_id,
    )

    if not can_cancel_analysis(
        request.user,
        analysis,
    ):
        raise PermissionDenied(
            "You do not have permission to cancel this analysis."
        )

    if request.method == "POST":
        form = AIAnalysisCancelForm(
            request.POST
        )

        if form.is_valid():
            cancellation_reason = form.cleaned_data[
                "cancellation_reason"
            ]
            previous_status = analysis.status
            transition_time = timezone.now()

            with transaction.atomic():
                updated_rows = (
                    AIAnalysis.objects
                    .filter(
                        pk=analysis.pk,
                        status=previous_status,
                        is_active=True,
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
                    current = get_accessible_analysis_or_404(
                        user=request.user,
                        analysis_id=analysis.pk,
                    )

                    messages.warning(
                        request,
                        (
                            "This analysis can no longer be cancelled because "
                            "its lifecycle state changed while the request was "
                            "being processed."
                        ),
                    )

                    return redirect(
                        "ai_engine:analysis_detail",
                        analysis_id=current.pk,
                    )

                analysis.refresh_from_db()

                create_analysis_log(
                    analysis=analysis,
                    event_type=(
                        AIAnalysisLog.EventType.CANCELLED
                    ),
                    message=(
                        "Analysis cancelled before completion."
                    ),
                    actor=request.user,
                    metadata={
                        "reason": cancellation_reason,
                        "previous_status": previous_status,
                        "transition_strategy": (
                            "atomic_compare_and_set"
                        ),
                    },
                )

            messages.success(
                request,
                (
                    f"Analysis '{analysis.title}' "
                    "was cancelled successfully."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        messages.error(
            request,
            (
                "Cancellation could not be completed. Tick the confirmation "
                "checkbox and enter a valid cancellation reason."
            ),
        )

    else:
        form = AIAnalysisCancelForm()

    context = get_common_context(
        request
    )

    context.update({
        "page_title": "Cancel AI Analysis",
        "page_subtitle": analysis.title,
        "analysis": analysis,
        "form": form,
    })

    return render(
        request,
        "ai_engine/analysis_cancel.html",
        context,
    )


# ============================================================================
# Human Review
# ============================================================================

@ai_role_required(
    ROLE_ADMINISTRATOR,
    ROLE_CYBER_OFFICER,
)
@require_http_methods(["GET", "POST"])
def analysis_review(
    request: HttpRequest,
    analysis_id: Any,
) -> HttpResponse:
    """
    Record or update a Human Review with optimistic concurrency protection.

    A signed version token is rendered with the form. The final database
    UPDATE also requires updated_date to still equal the version that was
    displayed to the reviewer. This prevents two reviewers from silently
    overwriting one another, including on SQLite.
    """

    analysis = get_accessible_analysis_or_404(
        user=request.user,
        analysis_id=analysis_id,
    )

    if not can_review_analysis(
        request.user,
        analysis,
    ):
        raise PermissionDenied(
            "You do not have permission to review this analysis."
        )

    if request.method == "POST":
        submitted_review_version = (
            request.POST.get(
                "review_version",
                "",
            )
            or ""
        ).strip()

        if not review_version_matches(
            analysis,
            submitted_review_version,
        ):
            messages.warning(
                request,
                (
                    "This analysis was changed after the review page was "
                    "opened. The submitted review was not saved. Review the "
                    "latest information and submit again."
                ),
            )

            return redirect(
                "ai_engine:analysis_review",
                analysis_id=analysis.pk,
            )

        form = AIAnalysisReviewForm(
            request.POST,
            instance=analysis,
            current_user=request.user,
        )

        review_version = submitted_review_version

        if form.is_valid():
            review_notes = form.cleaned_data[
                "review_notes"
            ]
            previous_reviewer_id = (
                analysis.reviewed_by_id
            )
            previous_reviewed_at = (
                analysis.reviewed_at
            )
            previous_updated_date = (
                analysis.updated_date
            )
            reviewed_at = timezone.now()

            with transaction.atomic():
                updated_rows = (
                    AIAnalysis.objects
                    .filter(
                        pk=analysis.pk,
                        is_active=True,
                        status__in={
                            AIAnalysis.Status.COMPLETED,
                            AIAnalysis.Status.FAILED,
                        },
                        updated_date=previous_updated_date,
                    )
                    .update(
                        review_notes=review_notes,
                        reviewed_by_id=request.user.pk,
                        reviewed_at=reviewed_at,
                        updated_date=reviewed_at,
                    )
                )

                if updated_rows != 1:
                    messages.warning(
                        request,
                        (
                            "Another reviewer changed this analysis while "
                            "your review was being saved. Your review was "
                            "not written. Reload the current review and try "
                            "again."
                        ),
                    )

                    return redirect(
                        "ai_engine:analysis_review",
                        analysis_id=analysis.pk,
                    )

                reviewed_analysis = (
                    get_accessible_analysis_or_404(
                        user=request.user,
                        analysis_id=analysis.pk,
                    )
                )

                create_analysis_log(
                    analysis=reviewed_analysis,
                    event_type=AIAnalysisLog.EventType.REVIEWED,
                    message=(
                        "Human review recorded for the AI analysis."
                    ),
                    actor=request.user,
                    metadata={
                        "reviewed_at": (
                            reviewed_analysis.reviewed_at.isoformat()
                            if reviewed_analysis.reviewed_at
                            else None
                        ),
                        "previous_reviewer_id": (
                            str(previous_reviewer_id)
                            if previous_reviewer_id
                            else None
                        ),
                        "previous_reviewed_at": (
                            previous_reviewed_at.isoformat()
                            if previous_reviewed_at
                            else None
                        ),
                        "review_was_update": bool(
                            previous_reviewed_at
                        ),
                        "transition_strategy": (
                            "signed_version_atomic_compare_and_set"
                        ),
                    },
                )

            messages.success(
                request,
                "Human review was saved successfully.",
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=reviewed_analysis.pk,
            )

    else:
        form = AIAnalysisReviewForm(
            instance=analysis,
            current_user=request.user,
        )

        review_version = build_review_version_token(
            analysis
        )

    context = get_common_context(request)

    context.update({
        "page_title": "Review AI Analysis",
        "page_subtitle": analysis.title,
        "analysis": analysis,
        "form": form,
        "review_version": review_version,
    })

    return render(
        request,
        "ai_engine/analysis_review.html",
        context,
    )


# ============================================================================
# Archive Analysis
# ============================================================================

@ai_role_required(
    ROLE_ADMINISTRATOR,
    ROLE_CYBER_OFFICER,
)
@require_http_methods(["GET", "POST"])
def analysis_archive(
    request: HttpRequest,
    analysis_id: Any,
) -> HttpResponse:
    """
    Archive an analysis without deleting results or audit history.

    The active->archived transition is a conditional database UPDATE. It also
    requires the lifecycle status to remain unchanged, preventing Archive from
    overwriting a concurrent Run/worker transition on SQLite.
    """

    analysis = get_accessible_analysis_or_404(
        user=request.user,
        analysis_id=analysis_id,
    )

    if not can_archive_analysis(
        request.user,
        analysis,
    ):
        if analysis.status in {
            AIAnalysis.Status.QUEUED,
            AIAnalysis.Status.PROCESSING,
        }:
            messages.warning(
                request,
                (
                    "An analysis cannot be archived while it is queued or "
                    "processing. Wait for execution to finish or cancel it "
                    "before archiving."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        raise PermissionDenied(
            "You do not have permission to archive this analysis."
        )

    if request.method == "POST":
        form = AIAnalysisArchiveForm(
            request.POST
        )

        if form.is_valid():
            archive_reason = (
                form.cleaned_data.get(
                    "reason",
                    "",
                )
                or ""
            ).strip()

            previous_status = analysis.status
            transition_time = timezone.now()

            with transaction.atomic():
                updated_rows = (
                    AIAnalysis.objects
                    .filter(
                        pk=analysis.pk,
                        is_active=True,
                        status=previous_status,
                    )
                    .exclude(
                        status__in={
                            AIAnalysis.Status.QUEUED,
                            AIAnalysis.Status.PROCESSING,
                        }
                    )
                    .update(
                        is_active=False,
                        updated_date=transition_time,
                    )
                )

                if updated_rows != 1:
                    current = get_accessible_analysis_or_404(
                        user=request.user,
                        analysis_id=analysis.pk,
                    )

                    messages.warning(
                        request,
                        (
                            "The analysis changed while the archive request "
                            "was being processed, so it was not archived."
                        ),
                    )

                    return redirect(
                        "ai_engine:analysis_detail",
                        analysis_id=current.pk,
                    )

                analysis.refresh_from_db()

                create_analysis_log(
                    analysis=analysis,
                    event_type=(
                        AIAnalysisLog.EventType.ARCHIVED
                    ),
                    message=(
                        "AI analysis archived without deleting results."
                    ),
                    actor=request.user,
                    metadata={
                        "reason": archive_reason,
                        "previous_status": previous_status,
                        "transition_strategy": (
                            "atomic_compare_and_set"
                        ),
                    },
                )

            messages.success(
                request,
                (
                    f"Analysis '{analysis.title}' "
                    "was archived successfully."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        messages.error(
            request,
            (
                "The analysis could not be archived. Complete the required "
                "confirmation and correct the highlighted fields."
            ),
        )

    else:
        form = AIAnalysisArchiveForm()

    context = get_common_context(
        request
    )

    context.update({
        "page_title": "Archive AI Analysis",
        "page_subtitle": analysis.title,
        "analysis": analysis,
        "form": form,
    })

    return render(
        request,
        "ai_engine/analysis_archive.html",
        context,
    )


# ============================================================================
# Restore Analysis
# ============================================================================

@ai_role_required(
    ROLE_ADMINISTRATOR,
    ROLE_CYBER_OFFICER,
)
@require_POST
def analysis_restore(
    request: HttpRequest,
    analysis_id: Any,
) -> HttpResponse:
    """
    Restore an archived AI analysis with an atomic inactive->active
    transition.

    Only the request that actually changes is_active from False to True writes
    the RESTORED audit event, preventing duplicate restore logs on SQLite.
    """

    analysis = get_accessible_analysis_or_404(
        user=request.user,
        analysis_id=analysis_id,
    )

    if not can_restore_analysis(
        request.user,
        analysis,
    ):
        if analysis.is_active:
            messages.warning(
                request,
                "This analysis is already active.",
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        if not analysis.evidence.is_active:
            messages.warning(
                request,
                (
                    "Restore the linked evidence before restoring "
                    "this AI analysis."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=analysis.pk,
            )

        raise PermissionDenied(
            "You do not have permission to restore this analysis."
        )

    previous_status = analysis.status
    transition_time = timezone.now()

    with transaction.atomic():
        updated_rows = (
            AIAnalysis.objects
            .filter(
                pk=analysis.pk,
                is_active=False,
                status=previous_status,
                evidence__is_active=True,
            )
            .update(
                is_active=True,
                updated_date=transition_time,
            )
        )

        if updated_rows != 1:
            current = get_accessible_analysis_or_404(
                user=request.user,
                analysis_id=analysis.pk,
            )

            messages.warning(
                request,
                (
                    "The analysis changed while the restore request was being "
                    "processed. Refresh the page to see its current state."
                ),
            )

            return redirect(
                "ai_engine:analysis_detail",
                analysis_id=current.pk,
            )

        analysis.refresh_from_db()

        create_analysis_log(
            analysis=analysis,
            event_type=AIAnalysisLog.EventType.RESTORED,
            message="AI analysis restored.",
            actor=request.user,
            metadata={
                "previous_status": previous_status,
                "transition_strategy": "atomic_compare_and_set",
            },
        )

    messages.success(
        request,
        (
            f"Analysis '{analysis.title}' "
            "was restored successfully."
        ),
    )

    return redirect(
        "ai_engine:analysis_detail",
        analysis_id=analysis.pk,
    )