"""
AIDEX Dashboard Views

Provides secure role-based dashboards for:

- Administrator
- Investigator
- Cyber Officer

Features:

- Role-based access control
- Case analytics
- Evidence analytics
- Report analytics
- User statistics
- Review queues
- Recent activities
- Chart-ready data
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q, QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET

from cases.models import Case
from evidence.models import Evidence
from reports.models import Report


User = get_user_model()


# ==========================================================
# Role Configuration
# ==========================================================

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


# ==========================================================
# Role Utilities
# ==========================================================

def normalize_role(
    role_value: Any,
) -> str:
    """
    Convert different role formats into a standard value.
    """

    normalized_role = (
        str(role_value or "")
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return ROLE_ALIASES.get(
        normalized_role,
        normalized_role,
    )


def get_user_role(
    user: Any,
) -> str:
    """
    Return the normalized role of an authenticated user.
    """

    if getattr(user, "is_superuser", False):
        return ROLE_ADMINISTRATOR

    return normalize_role(
        getattr(user, "role", "")
    )


def get_user_display_name(
    user: Any,
) -> str:
    """
    Return the best available name for a user.
    """

    if user is None:
        return "Not assigned"

    full_name = str(
        getattr(user, "full_name", "") or ""
    ).strip()

    if full_name:
        return full_name

    get_full_name_method = getattr(
        user,
        "get_full_name",
        None,
    )

    if callable(get_full_name_method):
        django_full_name = str(
            get_full_name_method() or ""
        ).strip()

        if django_full_name:
            return django_full_name

    return str(
        getattr(
            user,
            "username",
            "Unknown User",
        )
    )


def calculate_percentage(
    part: int,
    total: int,
) -> int:
    """
    Calculate a safe whole-number percentage.

    Returns zero when the total value is zero.
    The final value is always limited to the range 0-100.
    """

    if total <= 0:
        return 0

    percentage = round(
        (part / total) * 100
    )

    return max(
        0,
        min(
            percentage,
            100,
        ),
    )


# ==========================================================
# Role Required Decorator
# ==========================================================

def role_required(
    *allowed_roles: str,
) -> Callable:
    """
    Restrict a view to selected AIDEX roles.
    """

    normalized_allowed_roles = {
        normalize_role(role)
        for role in allowed_roles
    }

    def decorator(
        view_function: Callable,
    ) -> Callable:

        @wraps(view_function)
        @login_required
        def wrapper(
            request: HttpRequest,
            *args: Any,
            **kwargs: Any,
        ) -> HttpResponse:

            current_role = get_user_role(
                request.user
            )

            if current_role not in normalized_allowed_roles:
                raise PermissionDenied(
                    "You do not have permission to access this dashboard."
                )

            return view_function(
                request,
                *args,
                **kwargs,
            )

        return wrapper

    return decorator


# ==========================================================
# Dashboard Helper Functions
# ==========================================================

def get_choice_statistics(
    queryset: QuerySet,
    field_name: str,
    choices: Any,
) -> list[dict[str, Any]]:
    """
    Return chart-ready statistics for a model choice field.
    """

    database_rows = (
        queryset
        .values(field_name)
        .annotate(total=Count("id"))
        .order_by()
    )

    database_counts = {
        row[field_name]: row["total"]
        for row in database_rows
    }

    return [
        {
            "key": value,
            "label": label,
            "total": database_counts.get(
                value,
                0,
            ),
        }
        for value, label in choices
    ]


def get_recent_activities(
    case_queryset: QuerySet,
    evidence_queryset: QuerySet,
    report_queryset: QuerySet,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Combine recent Case, Evidence and Report activities.
    """

    activities: list[dict[str, Any]] = []

    recent_cases = (
        case_queryset
        .select_related(
            "created_by",
            "assigned_investigator",
        )
        .order_by("-updated_date")[:limit]
    )

    for case in recent_cases:
        activities.append({
            "activity_type": "CASE",
            "title": case.case_title,
            "description": (
                f"Case {case.case_number} is currently "
                f"{case.get_status_display()}."
            ),
            "performed_by": get_user_display_name(
                case.created_by
            ),
            "timestamp": case.updated_date,
            "icon": "bi-folder2-open",
            "color": "primary",
            "object_id": str(case.pk),
        })

    recent_evidence = (
        evidence_queryset
        .select_related(
            "case",
            "uploaded_by",
            "verified_by",
        )
        .order_by("-updated_date")[:limit]
    )

    for evidence_item in recent_evidence:
        activities.append({
            "activity_type": "EVIDENCE",
            "title": evidence_item.evidence_title,
            "description": (
                f"Evidence for "
                f"{evidence_item.case.case_number} is "
                f"{evidence_item.get_verification_status_display()}."
            ),
            "performed_by": get_user_display_name(
                evidence_item.uploaded_by
            ),
            "timestamp": evidence_item.updated_date,
            "icon": "bi-file-earmark-lock",
            "color": "info",
            "object_id": str(evidence_item.pk),
        })

    recent_reports = (
        report_queryset
        .select_related(
            "case",
            "generated_by",
            "reviewed_by",
            "approved_by",
        )
        .order_by("-updated_date")[:limit]
    )

    for report in recent_reports:
        activities.append({
            "activity_type": "REPORT",
            "title": report.report_title,
            "description": (
                f"Report {report.report_number} is currently "
                f"{report.get_status_display()}."
            ),
            "performed_by": get_user_display_name(
                report.generated_by
            ),
            "timestamp": report.updated_date,
            "icon": "bi-file-earmark-text",
            "color": "success",
            "object_id": str(report.pk),
        })

    activities.sort(
        key=lambda activity: activity["timestamp"],
        reverse=True,
    )

    return activities[:limit]


def get_base_dashboard_context(
    request: HttpRequest,
    title: str,
    subtitle: str,
) -> dict[str, Any]:
    """
    Return common dashboard context.
    """

    return {
        "dashboard_title": title,
        "dashboard_subtitle": subtitle,
        "current_user": request.user,
        "current_role": get_user_role(
            request.user
        ),
        "current_date": timezone.localdate(),
    }


# ==========================================================
# Public Landing Page
# ==========================================================

@require_GET
def landing_page(
    request: HttpRequest,
) -> HttpResponse:
    """
    Public AIDEX landing page.

    Anonymous visitors see the product introduction, capabilities and
    demonstration feedback cards before choosing Sign Up or Login.
    Authenticated users are sent directly to their role dashboard.
    """

    if request.user.is_authenticated:
        return redirect(
            "dashboard:dashboard_redirect"
        )

    context = {
        "page_title": "AIDEX",
        "page_subtitle": (
            "AI Digital Evidence Intelligence System"
        ),
        "feature_cards": [
            {
                "icon": "bi-shield-lock",
                "title": "Evidence Integrity",
                "description": (
                    "SHA-256 hashing, verification workflows and "
                    "controlled evidence lifecycle management."
                ),
            },
            {
                "icon": "bi-cpu",
                "title": "AI-Assisted Analysis",
                "description": (
                    "Versioned forensic prompts, local extraction and "
                    "multimodal AI analysis with audit-aware execution."
                ),
            },
            {
                "icon": "bi-folder2-open",
                "title": "Case Investigation",
                "description": (
                    "Role-aware cyber-crime case management from assignment "
                    "through evidence collection, analysis and closure."
                ),
            },
            {
                "icon": "bi-clipboard2-check",
                "title": "Verification Workflow",
                "description": (
                    "Structured evidence review states with reviewer "
                    "attribution and integrity-check support."
                ),
            },
        ],
        "workflow_steps": [
            {
                "number": "01",
                "title": "Register Case",
                "description": (
                    "Create and assign an investigation with controlled "
                    "case-status transitions."
                ),
            },
            {
                "number": "02",
                "title": "Collect Evidence",
                "description": (
                    "Upload evidence while preserving filename, hash and "
                    "forensic metadata."
                ),
            },
            {
                "number": "03",
                "title": "Analyze Securely",
                "description": (
                    "Run local extraction and explicit AI-assisted analysis "
                    "without silent provider calls."
                ),
            },
            {
                "number": "04",
                "title": "Review Findings",
                "description": (
                    "Verify evidence, inspect analysis output and maintain "
                    "an auditable investigation trail."
                ),
            },
        ],
        # These are clearly labelled as demonstration feedback, not real
        # customer testimonials.
        "review_cards": [
            {
                "role": "Investigator workflow",
                "rating": 5,
                "text": (
                    "The interface keeps case, evidence and analysis actions "
                    "in one clear investigation flow."
                ),
            },
            {
                "role": "Evidence review workflow",
                "rating": 5,
                "text": (
                    "Integrity checks and verification states make the "
                    "evidence review process easy to follow."
                ),
            },
            {
                "role": "Administrator workflow",
                "rating": 5,
                "text": (
                    "Role-based dashboards provide a concise operational "
                    "view of investigations and evidence."
                ),
            },
        ],
    }

    return render(
        request,
        "landing.html",
        context,
    )


# ==========================================================
# Dashboard Redirect
# ==========================================================

@login_required
@require_GET
def dashboard_redirect(
    request: HttpRequest,
) -> HttpResponse:
    """
    Redirect users to their assigned role dashboard.
    """

    user_role = get_user_role(
        request.user
    )

    dashboard_routes = {
        ROLE_ADMINISTRATOR: (
            "dashboard:admin_dashboard"
        ),
        ROLE_INVESTIGATOR: (
            "dashboard:investigator_dashboard"
        ),
        ROLE_CYBER_OFFICER: (
            "dashboard:cyber_officer_dashboard"
        ),
    }

    route_name = dashboard_routes.get(
        user_role
    )

    if route_name:
        return redirect(
            route_name
        )

    messages.error(
        request,
        (
            "Your account does not have a valid dashboard role. "
            "Please contact the system administrator."
        ),
    )

    return redirect(
        "accounts:profile"
    )


# ==========================================================
# Administrator Dashboard
# ==========================================================

@role_required(ROLE_ADMINISTRATOR)
@require_GET
def admin_dashboard(
    request: HttpRequest,
) -> HttpResponse:
    """
    Administrator dashboard containing system-wide analytics.
    """

    today = timezone.localdate()

    users = User.objects.all()
    cases = Case.objects.all()
    evidence_items = Evidence.objects.all()
    reports = Report.objects.all()

    active_case_statuses = {
        Case.Status.OPEN,
        Case.Status.ASSIGNED,
        Case.Status.UNDER_INVESTIGATION,
        Case.Status.EVIDENCE_COLLECTION,
        Case.Status.AI_ANALYSIS,
        Case.Status.REPORT_GENERATION,
    }

    total_users = users.count()

    active_users = users.filter(
        is_active=True
    ).count()

    total_cases = cases.count()

    active_cases = cases.filter(
        status__in=active_case_statuses,
        is_active=True,
    ).count()

    closed_cases = cases.filter(
        status=Case.Status.CLOSED,
    ).count()

    critical_cases = cases.filter(
        priority=Case.Priority.CRITICAL,
        is_active=True,
    ).count()

    total_evidence = evidence_items.count()

    pending_evidence = evidence_items.filter(
        verification_status__in={
            Evidence.VerificationStatus.PENDING,
            Evidence.VerificationStatus.IN_REVIEW,
        },
        is_active=True,
    ).count()

    verified_evidence = evidence_items.filter(
        verification_status=(
            Evidence.VerificationStatus.VERIFIED
        ),
        is_active=True,
    ).count()

    total_reports = reports.count()

    reports_under_review = reports.filter(
        status=Report.Status.UNDER_REVIEW,
        is_active=True,
    ).count()

    approved_reports = reports.filter(
        status=Report.Status.APPROVED,
        is_active=True,
    ).count()

    context = get_base_dashboard_context(
        request=request,
        title="Administrator Dashboard",
        subtitle=(
            "System-wide users, cases, evidence and "
            "investigation report analytics."
        ),
    )

    context.update({
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": (
            total_users - active_users
        ),
        "total_investigators": users.filter(
            role__iexact="INVESTIGATOR",
            is_active=True,
        ).count(),
        "total_cyber_officers": users.filter(
            Q(role__iexact="CYBER_OFFICER")
            | Q(role__iexact="CYBER OFFICER"),
            is_active=True,
        ).count(),
        "total_cases": total_cases,
        "active_cases": active_cases,
        "closed_cases": closed_cases,
        "critical_cases": critical_cases,
        "cases_created_today": cases.filter(
            created_date__date=today
        ).count(),
        "total_evidence": total_evidence,
        "pending_evidence": pending_evidence,
        "verified_evidence": verified_evidence,
        "evidence_uploaded_today": (
            evidence_items.filter(
                uploaded_date__date=today
            ).count()
        ),
        "total_reports": total_reports,
        "reports_under_review": reports_under_review,
        "approved_reports": approved_reports,
        "reports_generated_today": reports.filter(
            generated_date__date=today
        ).count(),
        "recent_cases": (
            cases
            .select_related(
                "created_by",
                "assigned_investigator",
            )
            .order_by("-created_date")[:6]
        ),
        "recent_evidence": (
            evidence_items
            .select_related(
                "case",
                "uploaded_by",
            )
            .order_by("-uploaded_date")[:6]
        ),
        "recent_reports": (
            reports
            .select_related(
                "case",
                "generated_by",
            )
            .order_by("-generated_date")[:6]
        ),
        "recent_activities": get_recent_activities(
            case_queryset=cases,
            evidence_queryset=evidence_items,
            report_queryset=reports,
            limit=10,
        ),
        "case_status_chart": get_choice_statistics(
            queryset=cases,
            field_name="status",
            choices=Case.Status.choices,
        ),
        "case_priority_chart": get_choice_statistics(
            queryset=cases,
            field_name="priority",
            choices=Case.Priority.choices,
        ),
        "evidence_status_chart": get_choice_statistics(
            queryset=evidence_items,
            field_name="verification_status",
            choices=Evidence.VerificationStatus.choices,
        ),
        "report_status_chart": get_choice_statistics(
            queryset=reports,
            field_name="status",
            choices=Report.Status.choices,
        ),
    })

    return render(
        request,
        "dashboard/admin_dashboard.html",
        context,
    )


# ==========================================================
# Investigator Dashboard
# ==========================================================

@role_required(ROLE_INVESTIGATOR)
@require_GET
def investigator_dashboard(
    request: HttpRequest,
) -> HttpResponse:
    """
    Investigator dashboard limited to assigned cases.
    """

    investigator = request.user

    assigned_cases = Case.objects.filter(
        assigned_investigator=investigator
    )

    assigned_evidence = Evidence.objects.filter(
        case__assigned_investigator=investigator
    )

    assigned_reports = (
        Report.objects
        .filter(
            Q(
                case__assigned_investigator=investigator
            )
            | Q(
                generated_by=investigator
            )
        )
        .distinct()
    )

    active_case_statuses = {
        Case.Status.OPEN,
        Case.Status.ASSIGNED,
        Case.Status.UNDER_INVESTIGATION,
        Case.Status.EVIDENCE_COLLECTION,
        Case.Status.AI_ANALYSIS,
        Case.Status.REPORT_GENERATION,
    }

    total_assigned_cases = assigned_cases.count()

    active_assigned_cases = assigned_cases.filter(
        status__in=active_case_statuses,
        is_active=True,
    ).count()

    high_priority_cases = assigned_cases.filter(
        priority__in={
            Case.Priority.HIGH,
            Case.Priority.CRITICAL,
        },
        is_active=True,
    ).count()

    closed_assigned_cases = assigned_cases.filter(
        status=Case.Status.CLOSED
    ).count()

    total_case_evidence = assigned_evidence.count()

    pending_case_evidence = assigned_evidence.filter(
        verification_status__in={
            Evidence.VerificationStatus.PENDING,
            Evidence.VerificationStatus.IN_REVIEW,
        },
        is_active=True,
    ).count()

    verified_case_evidence = assigned_evidence.filter(
        verification_status=(
            Evidence.VerificationStatus.VERIFIED
        ),
        is_active=True,
    ).count()

    total_case_reports = assigned_reports.count()

    draft_reports = assigned_reports.filter(
        status=Report.Status.DRAFT,
        is_active=True,
    ).count()

    reports_under_review = assigned_reports.filter(
        status=Report.Status.UNDER_REVIEW,
        is_active=True,
    ).count()

    active_case_percentage = calculate_percentage(
        part=active_assigned_cases,
        total=total_assigned_cases,
    )

    verified_evidence_percentage = calculate_percentage(
        part=verified_case_evidence,
        total=total_case_evidence,
    )

    report_review_percentage = calculate_percentage(
        part=reports_under_review,
        total=total_case_reports,
    )

    context = get_base_dashboard_context(
        request=request,
        title="Investigator Dashboard",
        subtitle=(
            "Assigned investigations, digital evidence "
            "and report progress."
        ),
    )

    context.update({
        "total_assigned_cases": total_assigned_cases,
        "active_assigned_cases": active_assigned_cases,
        "high_priority_cases": high_priority_cases,
        "closed_assigned_cases": closed_assigned_cases,
        "total_case_evidence": total_case_evidence,
        "pending_case_evidence": pending_case_evidence,
        "verified_case_evidence": verified_case_evidence,
        "total_case_reports": total_case_reports,
        "draft_reports": draft_reports,
        "reports_under_review": reports_under_review,
        "active_case_percentage": active_case_percentage,
        "verified_evidence_percentage": (
            verified_evidence_percentage
        ),
        "report_review_percentage": report_review_percentage,
        "assigned_cases": (
            assigned_cases
            .select_related(
                "created_by",
                "assigned_investigator",
            )
            .order_by("-updated_date")[:8]
        ),
        "recent_evidence": (
            assigned_evidence
            .select_related(
                "case",
                "uploaded_by",
            )
            .order_by("-uploaded_date")[:6]
        ),
        "recent_reports": (
            assigned_reports
            .select_related(
                "case",
                "generated_by",
            )
            .order_by("-generated_date")[:6]
        ),
        "recent_activities": get_recent_activities(
            case_queryset=assigned_cases,
            evidence_queryset=assigned_evidence,
            report_queryset=assigned_reports,
            limit=10,
        ),
        "case_status_chart": get_choice_statistics(
            queryset=assigned_cases,
            field_name="status",
            choices=Case.Status.choices,
        ),
        "case_priority_chart": get_choice_statistics(
            queryset=assigned_cases,
            field_name="priority",
            choices=Case.Priority.choices,
        ),
        "evidence_status_chart": get_choice_statistics(
            queryset=assigned_evidence,
            field_name="verification_status",
            choices=Evidence.VerificationStatus.choices,
        ),
    })

    return render(
        request,
        "dashboard/investigator_dashboard.html",
        context,
    )


# ==========================================================
# Cyber Officer Dashboard
# ==========================================================

@role_required(ROLE_CYBER_OFFICER)
@require_GET
def cyber_officer_dashboard(
    request: HttpRequest,
) -> HttpResponse:
    """
    Cyber Officer dashboard for evidence and report review.
    """

    active_cases = Case.objects.filter(
        is_active=True
    )

    active_evidence = Evidence.objects.filter(
        is_active=True
    )

    active_reports = Report.objects.filter(
        is_active=True
    )

    evidence_review_queue = active_evidence.filter(
        verification_status__in={
            Evidence.VerificationStatus.PENDING,
            Evidence.VerificationStatus.IN_REVIEW,
        }
    )

    report_review_queue = active_reports.filter(
        status=Report.Status.UNDER_REVIEW
    )

    context = get_base_dashboard_context(
        request=request,
        title="Cyber Officer Dashboard",
        subtitle=(
            "Evidence verification, report review "
            "and cyber-risk monitoring."
        ),
    )

    context.update({
        "total_active_cases": (
            active_cases.count()
        ),
        "high_risk_cases": active_cases.filter(
            priority__in={
                Case.Priority.HIGH,
                Case.Priority.CRITICAL,
            }
        ).count(),
        "ai_analysis_cases": active_cases.filter(
            status=Case.Status.AI_ANALYSIS
        ).count(),
        "total_evidence": (
            active_evidence.count()
        ),
        "evidence_pending_review": (
            evidence_review_queue.count()
        ),
        "verified_evidence": active_evidence.filter(
            verification_status=(
                Evidence.VerificationStatus.VERIFIED
            )
        ).count(),
        "rejected_evidence": active_evidence.filter(
            verification_status__in={
                Evidence.VerificationStatus.REJECTED,
                Evidence.VerificationStatus.CORRUPTED,
            }
        ).count(),
        "total_reports": (
            active_reports.count()
        ),
        "reports_pending_review": (
            report_review_queue.count()
        ),
        "approved_reports": active_reports.filter(
            status=Report.Status.APPROVED
        ).count(),
        "confidential_reports": active_reports.filter(
            is_confidential=True
        ).count(),
        "evidence_review_queue": (
            evidence_review_queue
            .select_related(
                "case",
                "uploaded_by",
            )
            .order_by("-uploaded_date")[:8]
        ),
        "report_review_queue": (
            report_review_queue
            .select_related(
                "case",
                "generated_by",
            )
            .order_by("-generated_date")[:8]
        ),
        "critical_cases": (
            active_cases
            .filter(
                priority=Case.Priority.CRITICAL
            )
            .select_related(
                "created_by",
                "assigned_investigator",
            )
            .order_by("-updated_date")[:6]
        ),
        "recent_activities": get_recent_activities(
            case_queryset=active_cases,
            evidence_queryset=active_evidence,
            report_queryset=active_reports,
            limit=10,
        ),
        "case_status_chart": get_choice_statistics(
            queryset=active_cases,
            field_name="status",
            choices=Case.Status.choices,
        ),
        "evidence_status_chart": get_choice_statistics(
            queryset=active_evidence,
            field_name="verification_status",
            choices=Evidence.VerificationStatus.choices,
        ),
        "report_status_chart": get_choice_statistics(
            queryset=active_reports,
            field_name="status",
            choices=Report.Status.choices,
        ),
    })

    return render(
        request,
        "dashboard/cyber_officer_dashboard.html",
        context,
    )