"""
AIDEX Reports Views

Professional web views for the investigation-report module.

This layer intentionally keeps report lifecycle mutations inside
``reports.services`` so workflow rules, row locking and audit logging stay
centralized and consistent.

Expected templates
------------------
reports/dashboard.html
reports/report_list.html
reports/report_detail.html
reports/report_form.html
reports/report_submit_review.html
reports/report_review.html
reports/report_approve.html
reports/report_reject.html
reports/report_publish.html
reports/report_archive.html
reports/report_restore.html
reports/report_revision.html
reports/report_audit.html
reports/report_print.html
"""

from __future__ import annotations

import mimetypes
import os
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q
from django.http import (
    FileResponse,
    Http404,
    HttpRequest,
    HttpResponse,
)
from django.shortcuts import (
    get_object_or_404,
    redirect,
    render,
)
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import (
    require_http_methods,
    require_POST,
)

from .forms import (
    ReportApproveForm,
    ReportArchiveForm,
    ReportFilterForm,
    ReportForm,
    ReportPublishForm,
    ReportRejectForm,
    ReportRestoreForm,
    ReportReviewForm,
    ReportRevisionForm,
    ReportSubmitForReviewForm,
    get_accessible_case_queryset,
)
from .models import Report, ReportAuditLog
from .services import (
    ReportAccessError,
    ReportRevisionError,
    ReportServiceError,
    ReportStateError,
    approve_report,
    archive_report,
    can_approve_report,
    can_archive_report,
    can_create_report,
    can_create_revision,
    can_download_report,
    can_edit_report,
    can_publish_report,
    can_reject_report,
    can_restore_report,
    can_review_report,
    can_submit_report,
    can_view_report_audit,
    create_report_revision,
    get_accessible_reports,
    get_user_role,
    publish_report,
    record_report_created,
    record_report_download,
    record_report_review,
    record_report_updated,
    reject_report,
    restore_report,
    submit_report_for_review,
    verify_report_file_integrity,
)


REPORTS_PER_PAGE = 20
AUDIT_EVENTS_PER_PAGE = 30

ALLOWED_REPORT_ORDERING = {
    "-generated_date",
    "generated_date",
    "report_title",
    "-report_title",
    "status",
    "report_type",
    "-updated_date",
}


REPORT_EDIT_VERSION_SALT = "reports.report_edit.version"


def build_report_edit_version(
    report: Report,
) -> str:
    """
    Build a signed optimistic-lock token for the exact report version shown
    on the edit page.
    """

    return signing.dumps(
        {
            "report_id": str(report.pk),
            "updated_date": (
                report.updated_date.isoformat()
                if report.updated_date
                else ""
            ),
            "status": report.status,
            "is_active": report.is_active,
        },
        salt=REPORT_EDIT_VERSION_SALT,
        compress=True,
    )


def report_edit_version_matches(
    report: Report,
    token: str,
) -> bool:
    """
    Return True only if the submitted edit token still matches the current
    persisted report state.
    """

    if not token:
        return False

    try:
        payload = signing.loads(
            token,
            salt=REPORT_EDIT_VERSION_SALT,
        )
    except signing.BadSignature:
        return False

    return (
        payload.get("report_id") == str(report.pk)
        and payload.get("updated_date")
        == (
            report.updated_date.isoformat()
            if report.updated_date
            else ""
        )
        and payload.get("status") == report.status
        and payload.get("is_active") == report.is_active
    )


# ============================================================================
# Helpers
# ============================================================================

def _report_detail_url(
    report: Report,
) -> str:
    return reverse(
        "reports:report_detail",
        kwargs={
            "report_id": report.pk,
        },
    )


def _get_accessible_report_or_404(
    request: HttpRequest,
    report_id: Any,
) -> Report:
    """
    Fetch a report only from the current user's accessible report queryset.
    """

    return get_object_or_404(
        get_accessible_reports(
            request.user,
            include_archived=True,
        ),
        pk=report_id,
    )


def _validation_error_text(
    exc: Exception,
) -> str:
    """
    Convert service/model ValidationError into a clean user-facing message.
    """

    if isinstance(
        exc,
        ValidationError,
    ):
        if hasattr(
            exc,
            "message_dict",
        ):
            parts: list[str] = []

            for field_name, errors in (
                exc.message_dict.items()
            ):
                label = (
                    str(field_name)
                    .replace("_", " ")
                    .strip()
                    .title()
                )

                for error in errors:
                    parts.append(
                        f"{label}: {error}"
                    )

            if parts:
                return " ".join(
                    parts
                )

        if hasattr(
            exc,
            "messages",
        ):
            return " ".join(
                str(message)
                for message in exc.messages
            )

    return (
        str(exc).strip()
        or exc.__class__.__name__
    )


def _handle_workflow_error(
    request: HttpRequest,
    exc: Exception,
) -> None:
    """
    Display one controlled workflow error.
    """

    message = _validation_error_text(
        exc
    )

    if isinstance(
        exc,
        ReportAccessError,
    ):
        messages.error(
            request,
            message,
        )
        return

    if isinstance(
        exc,
        (
            ReportStateError,
            ReportRevisionError,
            ReportServiceError,
            ValidationError,
        ),
    ):
        messages.error(
            request,
            message,
        )
        return

    messages.error(
        request,
        "The report action could not be completed.",
    )


def _build_report_capabilities(
    request: HttpRequest,
    report: Report,
) -> dict[str, bool]:
    """
    Return UI-safe action flags for the detail page.
    """

    user = request.user

    return {
        "can_edit": can_edit_report(
            user,
            report,
        ),
        "can_submit": can_submit_report(
            user,
            report,
        ),
        "can_review": can_review_report(
            user,
            report,
        ),
        "can_approve": can_approve_report(
            user,
            report,
        ),
        "can_reject": can_reject_report(
            user,
            report,
        ),
        "can_publish": can_publish_report(
            user,
            report,
        ),
        "can_archive": can_archive_report(
            user,
            report,
        ),
        "can_restore": can_restore_report(
            user,
            report,
        ),
        "can_create_revision": can_create_revision(
            user,
            report,
        ),
        "can_download": can_download_report(
            user,
            report,
        ),
        "can_view_audit": can_view_report_audit(
            user,
            report,
        ),
    }


def _apply_report_filters(
    queryset,
    cleaned_data: dict[str, Any],
):
    """
    Apply validated ReportFilterForm values to an accessible queryset.
    """

    search = (
        cleaned_data.get(
            "search",
            "",
        )
        or ""
    ).strip()

    if search:
        queryset = queryset.filter(
            Q(
                report_number__icontains=search
            )
            | Q(
                report_title__icontains=search
            )
            | Q(
                case__case_number__icontains=search
            )
            | Q(
                case__case_title__icontains=search
            )
            | Q(
                summary__icontains=search
            )
            | Q(
                findings__icontains=search
            )
        )

    case = cleaned_data.get(
        "case"
    )

    if case is not None:
        queryset = queryset.filter(
            case=case
        )

    report_type = cleaned_data.get(
        "report_type"
    )

    if report_type:
        queryset = queryset.filter(
            report_type=report_type
        )

    status = cleaned_data.get(
        "status"
    )

    if status:
        queryset = queryset.filter(
            status=status
        )

    generated_by = cleaned_data.get(
        "generated_by"
    )

    if generated_by is not None:
        queryset = queryset.filter(
            generated_by=generated_by
        )

    confidentiality = cleaned_data.get(
        "confidentiality"
    )

    if confidentiality == "confidential":
        queryset = queryset.filter(
            is_confidential=True
        )

    elif confidentiality == "standard":
        queryset = queryset.filter(
            is_confidential=False
        )

    record_state = cleaned_data.get(
        "record_state"
    )

    if record_state == "active":
        queryset = queryset.filter(
            is_active=True
        ).exclude(
            status=Report.Status.ARCHIVED
        )

    elif record_state == "archived":
        queryset = queryset.filter(
            status=Report.Status.ARCHIVED,
            is_active=False,
        )

    ordering = (
        cleaned_data.get(
            "ordering"
        )
        or "-generated_date"
    )

    if ordering not in ALLOWED_REPORT_ORDERING:
        ordering = "-generated_date"

    return queryset.order_by(
        ordering
    )


# ============================================================================
# Dashboard / Listing
# ============================================================================

@login_required
@require_http_methods(
    [
        "GET",
    ]
)
def report_dashboard(
    request: HttpRequest,
) -> HttpResponse:
    """
    Professional reports overview for the current user's accessible scope.
    """

    accessible = get_accessible_reports(
        request.user,
        include_archived=True,
    )

    active_reports = accessible.filter(
        is_active=True
    ).exclude(
        status=Report.Status.ARCHIVED
    )

    status_counts = {
        "draft": active_reports.filter(
            status=Report.Status.DRAFT
        ).count(),
        "under_review": active_reports.filter(
            status=Report.Status.UNDER_REVIEW
        ).count(),
        "approved": active_reports.filter(
            status=Report.Status.APPROVED
        ).count(),
        "rejected": active_reports.filter(
            status=Report.Status.REJECTED
        ).count(),
        "published": active_reports.filter(
            status=Report.Status.PUBLISHED
        ).count(),
        "archived": accessible.filter(
            status=Report.Status.ARCHIVED
        ).count(),
    }

    reports_by_type = list(
        active_reports
        .values(
            "report_type"
        )
        .annotate(
            total=Count(
                "id"
            )
        )
        .order_by(
            "-total",
            "report_type",
        )
    )

    reports_by_status = list(
        accessible
        .values(
            "status"
        )
        .annotate(
            total=Count(
                "id"
            )
        )
        .order_by(
            "-total",
            "status",
        )
    )

    recent_reports = list(
        active_reports
        .select_related(
            "case",
            "generated_by",
        )
        .order_by(
            "-generated_date"
        )[:8]
    )

    review_queue = list(
        active_reports
        .filter(
            status=Report.Status.UNDER_REVIEW
        )
        .select_related(
            "case",
            "generated_by",
            "reviewed_by",
        )
        .order_by(
            "generated_date"
        )[:8]
    )

    context = {
        "page_title": "Reports Dashboard",
        "user_role": get_user_role(
            request.user
        ),
        "can_create_report": can_create_report(
            request.user
        ),
        "total_reports": accessible.count(),
        "active_reports_count": active_reports.count(),
        "confidential_reports_count": active_reports.filter(
            is_confidential=True
        ).count(),
        "my_reports_count": accessible.filter(
            generated_by=request.user
        ).count(),
        "status_counts": status_counts,
        "reports_by_type": reports_by_type,
        "reports_by_status": reports_by_status,
        "recent_reports": recent_reports,
        "review_queue": review_queue,
    }

    return render(
        request,
        "reports/dashboard.html",
        context,
    )


@login_required
@require_http_methods(
    [
        "GET",
    ]
)
def report_list(
    request: HttpRequest,
) -> HttpResponse:
    """
    Searchable and filterable report register.
    """

    queryset = get_accessible_reports(
        request.user,
        include_archived=True,
    )

    filter_form = ReportFilterForm(
        request.GET or None,
        current_user=request.user,
    )

    if filter_form.is_valid():
        queryset = _apply_report_filters(
            queryset,
            filter_form.cleaned_data,
        )
    else:
        queryset = queryset.order_by(
            "-generated_date"
        )

    paginator = Paginator(
        queryset,
        REPORTS_PER_PAGE,
    )

    page_obj = paginator.get_page(
        request.GET.get(
            "page"
        )
    )

    context = {
        "page_title": "Investigation Reports",
        "filter_form": filter_form,
        "page_obj": page_obj,
        "reports": page_obj.object_list,
        "result_count": paginator.count,
        "can_create_report": can_create_report(
            request.user
        ),
        "user_role": get_user_role(
            request.user
        ),
    }

    return render(
        request,
        "reports/report_list.html",
        context,
    )


# ============================================================================
# Detail
# ============================================================================

@login_required
@require_http_methods(
    [
        "GET",
    ]
)
def report_detail(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    evidence_items = (
        report.included_evidence
        .select_related(
            "case",
            "uploaded_by",
            "verified_by",
        )
        .order_by(
            "-uploaded_date"
        )
    )

    analysis_items = (
        report.included_analyses
        .select_related(
            "evidence",
            "created_by",
        )
        .order_by(
            "-completed_at",
            "-created_date",
        )
    )

    revisions = (
        report.revisions
        .select_related(
            "generated_by",
        )
        .order_by(
            "-version",
            "-generated_date",
        )
    )

    recent_audit = (
        report.audit_logs
        .select_related(
            "actor",
        )
        .order_by(
            "-created_at"
        )[:10]
    )

    context = {
        "page_title": report.report_title,
        "report": report,
        "capabilities": _build_report_capabilities(
            request,
            report,
        ),
        "evidence_items": evidence_items,
        "analysis_items": analysis_items,
        "revisions": revisions,
        "recent_audit": recent_audit,
        "user_role": get_user_role(
            request.user
        ),
    }

    return render(
        request,
        "reports/report_detail.html",
        context,
    )


# ============================================================================
# Create / Update
# ============================================================================

@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_create(
    request: HttpRequest,
) -> HttpResponse:
    if not can_create_report(
        request.user
    ):
        raise PermissionDenied(
            "You are not allowed to create investigation reports."
        )

    initial: dict[str, Any] = {}

    requested_case_id = request.GET.get(
        "case"
    )

    if requested_case_id:
        requested_case = (
            get_accessible_case_queryset(
                request.user
            )
            .filter(
                pk=requested_case_id
            )
            .first()
        )

        if requested_case is not None:
            initial[
                "case"
            ] = requested_case

    if request.method == "POST":
        form = ReportForm(
            request.POST,
            request.FILES,
            current_user=request.user,
        )

        if form.is_valid():
            try:
                with transaction.atomic():
                    report = form.save(
                        commit=True
                    )

                    record_report_created(
                        report,
                        actor=request.user,
                    )

            except (
                ValidationError,
                ReportServiceError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    (
                        f"Report {report.report_number} created successfully "
                        "as a Draft."
                    ),
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportForm(
            current_user=request.user,
            initial=initial,
        )

    return render(
        request,
        "reports/report_form.html",
        {
            "page_title": "Create Investigation Report",
            "form": form,
            "form_mode": "create",
        },
    )


@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_update(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    """
    Edit a report with stale-form overwrite protection.

    The browser carries a signed version token and the final write first
    performs an atomic compare-and-set claim. This prevents an older edit tab
    from silently overwriting a newer edit or lifecycle transition on SQLite.
    """

    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_edit_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            (
                "This report cannot be edited in its current state "
                "or by your role."
            )
        )

    if request.method == "POST":
        submitted_edit_version = (
            request.POST.get(
                "edit_version",
                "",
            )
            or ""
        ).strip()

        if not report_edit_version_matches(
            report,
            submitted_edit_version,
        ):
            messages.warning(
                request,
                (
                    "This report changed after the edit page was opened. "
                    "Your stale form was not saved. Reload the latest report "
                    "and apply your changes again."
                ),
            )

            return redirect(
                "reports:report_update",
                report_id=report.pk,
            )

        expected_updated_date = report.updated_date
        expected_status = report.status
        expected_is_active = report.is_active

        form = ReportForm(
            request.POST,
            request.FILES,
            instance=report,
            current_user=request.user,
        )

        edit_version = submitted_edit_version

        if form.is_valid():
            changed_fields = list(
                form.changed_data
            )

            try:
                with transaction.atomic():
                    claim_time = timezone.now()

                    claimed_rows = (
                        Report.objects
                        .filter(
                            pk=report.pk,
                            updated_date=expected_updated_date,
                            status=expected_status,
                            is_active=expected_is_active,
                        )
                        .update(
                            updated_date=claim_time,
                        )
                    )

                    if claimed_rows != 1:
                        raise ReportStateError(
                            (
                                "Another user changed this report while your "
                                "edit was being saved. Your changes were not "
                                "written. Reload the latest report and try "
                                "again."
                            )
                        )

                    form.instance.updated_date = claim_time

                    updated_report = form.save(
                        commit=True
                    )

                    record_report_updated(
                        updated_report,
                        actor=request.user,
                        changed_fields=changed_fields,
                    )

            except (
                ValidationError,
                ReportServiceError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    "Report updated successfully.",
                )

                return redirect(
                    "reports:report_detail",
                    report_id=updated_report.pk,
                )

    else:
        form = ReportForm(
            instance=report,
            current_user=request.user,
        )

        edit_version = build_report_edit_version(
            report
        )

    return render(
        request,
        "reports/report_form.html",
        {
            "page_title": f"Edit {report.report_number}",
            "form": form,
            "form_mode": "update",
            "report": report,
            "edit_version": edit_version,
        },
    )



# ============================================================================
# Review Workflow
# ============================================================================

@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_submit_review(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_submit_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot submit this report for review."
        )

    if request.method == "POST":
        form = ReportSubmitForReviewForm(
            request.POST
        )

        if form.is_valid():
            try:
                report = submit_report_for_review(
                    report,
                    actor=request.user,
                    submission_note=form.cleaned_data[
                        "submission_note"
                    ],
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    "Report submitted for formal review.",
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportSubmitForReviewForm()

    return render(
        request,
        "reports/report_submit_review.html",
        {
            "page_title": "Submit Report for Review",
            "report": report,
            "form": form,
        },
    )


@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_review(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_review_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot formally review this report."
        )

    if request.method == "POST":
        form = ReportReviewForm(
            request.POST
        )

        if form.is_valid():
            try:
                report = record_report_review(
                    report,
                    actor=request.user,
                    review_notes=form.cleaned_data[
                        "review_notes"
                    ],
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    "Formal review notes recorded successfully.",
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportReviewForm(
            initial={
                "review_notes": (
                    report.review_notes
                ),
            }
        )

    return render(
        request,
        "reports/report_review.html",
        {
            "page_title": "Review Investigation Report",
            "report": report,
            "form": form,
        },
    )


@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_approve(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_approve_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            (
                "This report is not ready for approval or your role "
                "cannot approve it."
            )
        )

    if request.method == "POST":
        form = ReportApproveForm(
            request.POST
        )

        if form.is_valid():
            try:
                report = approve_report(
                    report,
                    actor=request.user,
                    approval_notes=form.cleaned_data[
                        "approval_notes"
                    ],
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    "Report approved successfully.",
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportApproveForm()

    return render(
        request,
        "reports/report_approve.html",
        {
            "page_title": "Approve Investigation Report",
            "report": report,
            "form": form,
        },
    )


@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_reject(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_reject_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot reject this report."
        )

    if request.method == "POST":
        form = ReportRejectForm(
            request.POST
        )

        if form.is_valid():
            try:
                report = reject_report(
                    report,
                    actor=request.user,
                    rejection_reason=form.cleaned_data[
                        "rejection_reason"
                    ],
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    (
                        "Report rejected and returned for revision."
                    ),
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportRejectForm()

    return render(
        request,
        "reports/report_reject.html",
        {
            "page_title": "Reject Investigation Report",
            "report": report,
            "form": form,
        },
    )


@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_publish(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_publish_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "This report is not eligible for publication."
        )

    if request.method == "POST":
        form = ReportPublishForm(
            request.POST
        )

        if form.is_valid():
            try:
                report = publish_report(
                    report,
                    actor=request.user,
                    publication_note=form.cleaned_data[
                        "publication_note"
                    ],
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    "Approved report published successfully.",
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportPublishForm()

    return render(
        request,
        "reports/report_publish.html",
        {
            "page_title": "Publish Investigation Report",
            "report": report,
            "form": form,
        },
    )


# ============================================================================
# Archive / Restore
# ============================================================================

@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_archive(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_archive_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot archive this report."
        )

    if request.method == "POST":
        form = ReportArchiveForm(
            request.POST
        )

        if form.is_valid():
            try:
                report = archive_report(
                    report,
                    actor=request.user,
                    reason=form.cleaned_data[
                        "reason"
                    ],
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    "Report archived successfully.",
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportArchiveForm()

    return render(
        request,
        "reports/report_archive.html",
        {
            "page_title": "Archive Investigation Report",
            "report": report,
            "form": form,
        },
    )


@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_restore(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_restore_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot restore this report."
        )

    if request.method == "POST":
        form = ReportRestoreForm(
            request.POST
        )

        if form.is_valid():
            try:
                report = restore_report(
                    report,
                    actor=request.user,
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    (
                        "Report restored to "
                        f"{report.get_status_display()}."
                    ),
                )

                return redirect(
                    "reports:report_detail",
                    report_id=report.pk,
                )

    else:
        form = ReportRestoreForm()

    return render(
        request,
        "reports/report_restore.html",
        {
            "page_title": "Restore Investigation Report",
            "report": report,
            "form": form,
        },
    )


# ============================================================================
# Revision
# ============================================================================

@login_required
@require_http_methods(
    [
        "GET",
        "POST",
    ]
)
def report_revision_create(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_create_revision(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot create a revision of this report."
        )

    if request.method == "POST":
        form = ReportRevisionForm(
            request.POST
        )

        if form.is_valid():
            try:
                revision = create_report_revision(
                    report,
                    actor=request.user,
                    revision_reason=form.cleaned_data[
                        "revision_reason"
                    ],
                    revision_title=form.cleaned_data[
                        "revision_title"
                    ],
                    copy_report_file=form.cleaned_data[
                        "copy_report_file"
                    ],
                )

            except (
                ReportServiceError,
                ValidationError,
            ) as exc:
                _handle_workflow_error(
                    request,
                    exc,
                )

            else:
                messages.success(
                    request,
                    (
                        f"Draft revision v{revision.version} "
                        "created successfully."
                    ),
                )

                return redirect(
                    "reports:report_detail",
                    report_id=revision.pk,
                )

    else:
        form = ReportRevisionForm()

    return render(
        request,
        "reports/report_revision.html",
        {
            "page_title": "Create Report Revision",
            "report": report,
            "form": form,
        },
    )


# ============================================================================
# Audit History
# ============================================================================

@login_required
@require_http_methods(
    [
        "GET",
    ]
)
def report_audit(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_view_report_audit(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot view this report's audit history."
        )

    audit_queryset = (
        report.audit_logs
        .select_related(
            "actor",
        )
        .order_by(
            "-created_at"
        )
    )

    event_type = (
        request.GET.get(
            "event_type",
            ""
        )
        or ""
    ).strip()

    valid_event_types = {
        value
        for value, _ in (
            ReportAuditLog.EventType.choices
        )
    }

    if event_type in valid_event_types:
        audit_queryset = (
            audit_queryset.filter(
                event_type=event_type
            )
        )

    paginator = Paginator(
        audit_queryset,
        AUDIT_EVENTS_PER_PAGE,
    )

    page_obj = paginator.get_page(
        request.GET.get(
            "page"
        )
    )

    return render(
        request,
        "reports/report_audit.html",
        {
            "page_title": (
                f"Audit History — {report.report_number}"
            ),
            "report": report,
            "page_obj": page_obj,
            "audit_events": (
                page_obj.object_list
            ),
            "event_type_choices": (
                ReportAuditLog.EventType.choices
            ),
            "selected_event_type": (
                event_type
            ),
        },
    )


# ============================================================================
# File Integrity / Download / Print
# ============================================================================

@login_required
@require_POST
def report_integrity_check(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    """
    Explicitly verify a report file against its stored SHA-256 value.
    """

    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    result = verify_report_file_integrity(
        report
    )

    if not result.checked:
        messages.warning(
            request,
            (
                result.error
                or "Report file integrity could not be checked."
            ),
        )

    elif result.matched:
        messages.success(
            request,
            (
                "Report file integrity verified successfully. "
                "The SHA-256 hash matches the stored fingerprint."
            ),
        )

    else:
        messages.error(
            request,
            (
                "WARNING: Report file integrity verification failed. "
                "The calculated SHA-256 does not match the stored fingerprint."
            ),
        )

    return redirect(
        "reports:report_detail",
        report_id=report.pk,
    )


@login_required
@require_http_methods(
    [
        "GET",
    ]
)
def report_download(
    request: HttpRequest,
    report_id: Any,
) -> FileResponse:
    """
    Stream an authorized report file and record a download audit event.
    """

    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    if not can_download_report(
        request.user,
        report,
    ):
        raise PermissionDenied(
            "You cannot download this report."
        )

    if not report.report_file:
        raise Http404(
            "No report file is available."
        )

    download_name = os.path.basename(
        report.original_filename
        or report.report_file.name
        or f"{report.report_number}.pdf"
    )

    content_type = (
        mimetypes.guess_type(
            download_name
        )[0]
        or "application/octet-stream"
    )

    try:
        file_handle = (
            report.report_file.open(
                "rb"
            )
        )
    except (
        FileNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        raise Http404(
            "The stored report file could not be found."
        ) from exc

    try:
        record_report_download(
            report,
            actor=request.user,
        )
    except ReportServiceError as exc:
        try:
            file_handle.close()
        except Exception:
            pass

        raise PermissionDenied(
            "The report download could not be authorized."
        ) from exc

    response = FileResponse(
        file_handle,
        as_attachment=True,
        filename=download_name,
        content_type=content_type,
    )

    response[
        "Cache-Control"
    ] = "private, no-store, max-age=0"
    response["Pragma"] = "no-cache"
    response[
        "X-Content-Type-Options"
    ] = "nosniff"

    return response


@login_required
@require_http_methods(
    [
        "GET",
    ]
)
def report_print(
    request: HttpRequest,
    report_id: Any,
) -> HttpResponse:
    """
    Print-friendly human-readable report view.

    Actual PDF generation/export can build on this layout in the dedicated
    report rendering service.
    """

    report = _get_accessible_report_or_404(
        request,
        report_id,
    )

    return render(
        request,
        "reports/report_print.html",
        {
            "page_title": (
                f"{report.report_number} — Print View"
            ),
            "report": report,
            "evidence_items": (
                report.included_evidence
                .select_related(
                    "uploaded_by",
                    "verified_by",
                )
                .order_by(
                    "uploaded_date"
                )
            ),
            "analysis_items": (
                report.included_analyses
                .select_related(
                    "evidence",
                    "created_by",
                )
                .order_by(
                    "created_date"
                )
            ),
        },
    )
