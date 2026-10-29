"""
AIDEX Case Management Views
===========================

Professional role-aware workflows for:

- Case listing with search, filters and pagination
- Case creation and editing
- Investigator assignment
- Normal case-status updates
- Secure archive workflow
- Secure restore workflow
- Role-based case access

Cases are never permanently deleted by this module.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import (
    require_GET,
    require_POST,
    require_http_methods,
)

from .forms import (
    CaseArchiveForm,
    CaseAssignmentForm,
    CaseFilterForm,
    CaseForm,
    CaseRestoreForm,
    CaseStatusForm,
)
from .models import Case


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


CASE_EDIT_VERSION_SALT = "cases.case_edit.version"


def build_case_edit_version(
    case: Case,
) -> str:
    return signing.dumps(
        {
            "case_id": str(case.pk),
            "updated_date": (
                case.updated_date.isoformat()
                if case.updated_date
                else ""
            ),
            "status": case.status,
            "is_active": case.is_active,
        },
        salt=CASE_EDIT_VERSION_SALT,
        compress=True,
    )


def case_edit_version_matches(
    case: Case,
    token: str,
) -> bool:
    if not token:
        return False

    try:
        payload = signing.loads(
            token,
            salt=CASE_EDIT_VERSION_SALT,
        )
    except signing.BadSignature:
        return False

    return (
        payload.get("case_id") == str(case.pk)
        and payload.get("updated_date")
        == (
            case.updated_date.isoformat()
            if case.updated_date
            else ""
        )
        and payload.get("status") == case.status
        and payload.get("is_active") == case.is_active
    )


# ==========================================================
# Role and Access Utilities
# ==========================================================

def normalize_role(
    role_value: Any,
) -> str:
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
    if getattr(user, "is_superuser", False):
        return ROLE_ADMINISTRATOR

    return normalize_role(
        getattr(user, "role", "")
    )


def user_has_role(
    user: Any,
    *roles: str,
) -> bool:
    allowed_roles = {
        normalize_role(role)
        for role in roles
    }

    return get_user_role(user) in allowed_roles


def case_role_required(
    *allowed_roles: str,
) -> Callable:
    normalized_roles = {
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
            if get_user_role(request.user) not in normalized_roles:
                raise PermissionDenied(
                    "You do not have permission to perform this action."
                )

            return view_function(
                request,
                *args,
                **kwargs,
            )

        return wrapper

    return decorator


def get_accessible_cases(
    user: Any,
) -> QuerySet[Case]:
    queryset = Case.objects.select_related(
        "created_by",
        "assigned_investigator",
        "archived_by",
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
                | Q(assigned_investigator=user)
            )
            .distinct()
        )

    return queryset.none()


def get_accessible_case_or_404(
    user: Any,
    case_id: Any,
) -> Case:
    return get_object_or_404(
        get_accessible_cases(user),
        pk=case_id,
    )


def can_create_case(
    user: Any,
) -> bool:
    return user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_INVESTIGATOR,
        ROLE_CYBER_OFFICER,
    )


def can_update_case(
    user: Any,
    case: Case,
) -> bool:
    if (
        case.status == Case.Status.ARCHIVED
        or not case.is_active
    ):
        return False

    if user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return True

    if user_has_role(
        user,
        ROLE_INVESTIGATOR,
    ):
        return (
            case.assigned_investigator_id == user.pk
            or (
                case.created_by_id == user.pk
                and case.assigned_investigator_id is None
            )
        )

    return False


def can_assign_case(
    user: Any,
    case: Case | None = None,
) -> bool:
    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    if case is None:
        return True

    return (
        case.is_active
        and case.status != Case.Status.ARCHIVED
    )


def can_change_case_status(
    user: Any,
    case: Case,
) -> bool:
    if (
        case.status == Case.Status.ARCHIVED
        or not case.is_active
    ):
        return False

    if user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return True

    return (
        user_has_role(
            user,
            ROLE_INVESTIGATOR,
        )
        and case.assigned_investigator_id == user.pk
    )


def can_archive_case(
    user: Any,
    case: Case | None = None,
) -> bool:
    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    if case is None:
        return True

    return (
        case.is_active
        and case.status != Case.Status.ARCHIVED
    )


def can_restore_case(
    user: Any,
    case: Case | None = None,
) -> bool:
    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    if case is None:
        return True

    return (
        not case.is_active
        and case.status == Case.Status.ARCHIVED
    )


# ==========================================================
# Query and Filter Utilities
# ==========================================================

def apply_case_filters(
    queryset: QuerySet[Case],
    filter_form: CaseFilterForm,
) -> QuerySet[Case]:
    if not filter_form.is_valid():
        return queryset.order_by(
            "-created_date"
        )

    cleaned = filter_form.cleaned_data

    search_value = (
        cleaned.get("search", "")
        or ""
    ).strip()

    crime_category = cleaned.get(
        "crime_category"
    )
    priority = cleaned.get(
        "priority"
    )
    status = cleaned.get(
        "status"
    )
    assigned_investigator = cleaned.get(
        "assigned_investigator"
    )
    active_state = cleaned.get(
        "active_state"
    )
    ordering = (
        cleaned.get("ordering")
        or "-created_date"
    )

    if search_value:
        queryset = queryset.filter(
            Q(case_number__icontains=search_value)
            | Q(case_title__icontains=search_value)
            | Q(description__icontains=search_value)
            | Q(created_by__username__icontains=search_value)
            | Q(created_by__full_name__icontains=search_value)
            | Q(
                assigned_investigator__username__icontains=(
                    search_value
                )
            )
            | Q(
                assigned_investigator__full_name__icontains=(
                    search_value
                )
            )
        )

    if crime_category:
        queryset = queryset.filter(
            crime_category=crime_category
        )

    if priority:
        queryset = queryset.filter(
            priority=priority
        )

    if status:
        queryset = queryset.filter(
            status=status
        )

    if assigned_investigator:
        queryset = queryset.filter(
            assigned_investigator=assigned_investigator
        )

    if active_state == "active":
        queryset = queryset.filter(
            is_active=True
        )

    elif active_state == "inactive":
        queryset = queryset.filter(
            is_active=False
        )

    allowed_ordering = {
        "-created_date",
        "created_date",
        "case_title",
        "-case_title",
        "priority",
        "status",
    }

    if ordering not in allowed_ordering:
        ordering = "-created_date"

    return queryset.order_by(
        ordering
    )


def build_query_string(
    request: HttpRequest,
) -> str:
    query_parameters = request.GET.copy()
    query_parameters.pop(
        "page",
        None,
    )

    return query_parameters.urlencode()


def get_case_statistics(
    queryset: QuerySet[Case],
) -> dict[str, int]:
    active_statuses = {
        Case.Status.OPEN,
        Case.Status.ASSIGNED,
        Case.Status.UNDER_INVESTIGATION,
        Case.Status.EVIDENCE_COLLECTION,
        Case.Status.AI_ANALYSIS,
        Case.Status.REPORT_GENERATION,
    }

    return {
        "total_cases": queryset.count(),
        "active_cases": queryset.filter(
            is_active=True,
            status__in=active_statuses,
        ).count(),
        "high_priority_cases": queryset.filter(
            is_active=True,
            priority__in={
                Case.Priority.HIGH,
                Case.Priority.CRITICAL,
            },
        ).count(),
        "closed_cases": queryset.filter(
            status=Case.Status.CLOSED,
        ).count(),
        "archived_cases": queryset.filter(
            status=Case.Status.ARCHIVED,
            is_active=False,
        ).count(),
        "unassigned_cases": queryset.filter(
            assigned_investigator__isnull=True,
            is_active=True,
        ).count(),
    }


def get_common_case_context(
    request: HttpRequest,
) -> dict[str, Any]:
    return {
        "current_user": request.user,
        "current_role": get_user_role(
            request.user
        ),
        "can_create_case": can_create_case(
            request.user
        ),
        "can_assign_cases": can_assign_case(
            request.user
        ),
        "can_archive_cases": can_archive_case(
            request.user
        ),
        "can_restore_cases": can_restore_case(
            request.user
        ),
    }


# ==========================================================
# Case Home
# ==========================================================

@login_required
@require_GET
def case_home(
    request: HttpRequest,
) -> HttpResponse:
    return redirect(
        "cases:case_list"
    )


# ==========================================================
# Case List
# ==========================================================

@login_required
@require_GET
def case_list(
    request: HttpRequest,
) -> HttpResponse:
    accessible_cases = get_accessible_cases(
        request.user
    )

    filter_form = CaseFilterForm(
        request.GET or None
    )

    filtered_cases = apply_case_filters(
        queryset=accessible_cases,
        filter_form=filter_form,
    )

    paginator = Paginator(
        filtered_cases,
        12,
    )

    page_object = paginator.get_page(
        request.GET.get("page")
    )

    context = get_common_case_context(
        request
    )

    context.update({
        "page_title": "Case Management",
        "page_subtitle": (
            "Search, review and manage cyber-crime investigations."
        ),
        "filter_form": filter_form,
        "cases": page_object,
        "page_obj": page_object,
        "paginator": paginator,
        "query_string": build_query_string(
            request
        ),
        "result_count": filtered_cases.count(),
        **get_case_statistics(
            accessible_cases
        ),
    })

    return render(
        request,
        "cases/case_list.html",
        context,
    )


# ==========================================================
# Case Create
# ==========================================================

@case_role_required(
    ROLE_ADMINISTRATOR,
    ROLE_INVESTIGATOR,
    ROLE_CYBER_OFFICER,
)
@require_http_methods([
    "GET",
    "POST",
])
def case_create(
    request: HttpRequest,
) -> HttpResponse:
    if request.method == "POST":
        form = CaseForm(
            request.POST,
            current_user=request.user,
        )

        if form.is_valid():
            with transaction.atomic():
                case = form.save(
                    commit=False
                )

                case.created_by = request.user
                case.is_active = True

                if (
                    get_user_role(request.user)
                    == ROLE_INVESTIGATOR
                    and case.assigned_investigator_id is None
                ):
                    case.assigned_investigator = request.user

                    if case.status == Case.Status.OPEN:
                        case.status = Case.Status.ASSIGNED

                case.save()

            messages.success(
                request,
                (
                    f"Case {case.case_number} was created "
                    "successfully."
                ),
            )

            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

    else:
        form = CaseForm(
            current_user=request.user,
        )

    context = get_common_case_context(
        request
    )

    context.update({
        "page_title": "Create Case",
        "page_subtitle": (
            "Register a new cyber-crime investigation in AIDEX."
        ),
        "form": form,
        "submit_label": "Create Case",
        "cancel_url_name": "cases:case_list",
    })

    return render(
        request,
        "cases/case_create.html",
        context,
    )


# ==========================================================
# Case Detail
# ==========================================================

@login_required
@require_GET
def case_detail(
    request: HttpRequest,
    case_id: Any,
) -> HttpResponse:
    case = get_accessible_case_or_404(
        user=request.user,
        case_id=case_id,
    )

    user_can_update = can_update_case(
        request.user,
        case,
    )

    user_can_assign = can_assign_case(
        request.user,
        case,
    )

    user_can_change_status = can_change_case_status(
        request.user,
        case,
    )

    user_can_archive = can_archive_case(
        request.user,
        case,
    )

    user_can_restore = can_restore_case(
        request.user,
        case,
    )

    context = get_common_case_context(
        request
    )

    context.update({
        "page_title": case.case_title,
        "page_subtitle": case.case_number,
        "case": case,
        "can_update_case": user_can_update,
        "can_assign_case": user_can_assign,
        "can_change_status": user_can_change_status,
        "can_archive_case": user_can_archive,
        "can_restore_case": user_can_restore,
        "assignment_form": (
            CaseAssignmentForm(
                instance=case
            )
            if user_can_assign
            else None
        ),
        "status_form": (
            CaseStatusForm(
                instance=case,
                current_user=request.user,
            )
            if user_can_change_status
            else None
        ),
        "archive_form": (
            CaseArchiveForm()
            if user_can_archive
            else None
        ),
        "restore_form": (
            CaseRestoreForm()
            if user_can_restore
            else None
        ),
    })

    return render(
        request,
        "cases/case_detail.html",
        context,
    )


# ==========================================================
# Case Update
# ==========================================================

@login_required
@require_http_methods([
    "GET",
    "POST",
])
def case_update(
    request: HttpRequest,
    case_id: Any,
) -> HttpResponse:
    """
    Update case metadata with stale-form overwrite protection.

    A signed edit token protects old browser tabs and the final conditional
    UPDATE protects simultaneous writes on SQLite.
    """

    case = get_accessible_case_or_404(
        user=request.user,
        case_id=case_id,
    )

    if not can_update_case(
        request.user,
        case,
    ):
        if case.status == Case.Status.ARCHIVED:
            messages.warning(
                request,
                (
                    "Archived cases cannot be edited. "
                    "Restore the case first."
                ),
            )
            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

        raise PermissionDenied(
            "You do not have permission to update this case."
        )

    if request.method == "POST":
        edit_version = (
            request.POST.get(
                "edit_version",
                "",
            )
            or ""
        ).strip()

        if not case_edit_version_matches(
            case,
            edit_version,
        ):
            messages.warning(
                request,
                (
                    "This case changed after the edit page was opened. "
                    "Your stale form was not saved. Reload the latest case "
                    "and apply your changes again."
                ),
            )
            return redirect(
                "cases:case_update",
                case_id=case.pk,
            )

        expected_updated_date = case.updated_date
        expected_status = case.status
        expected_is_active = case.is_active

        form = CaseForm(
            request.POST,
            instance=case,
            current_user=request.user,
        )

        if form.is_valid():
            candidate = form.save(
                commit=False
            )
            candidate.full_clean()

            update_time = timezone.now()

            with transaction.atomic():
                updated_rows = (
                    Case.objects
                    .filter(
                        pk=case.pk,
                        updated_date=expected_updated_date,
                        status=expected_status,
                        is_active=expected_is_active,
                    )
                    .update(
                        case_title=candidate.case_title,
                        description=candidate.description,
                        crime_category=candidate.crime_category,
                        priority=candidate.priority,
                        status=candidate.status,
                        assigned_investigator_id=(
                            candidate.assigned_investigator_id
                        ),
                        is_active=candidate.is_active,
                        updated_date=update_time,
                    )
                )

                if updated_rows != 1:
                    messages.warning(
                        request,
                        (
                            "Another user changed this case while your edit "
                            "was being saved. Your changes were not written. "
                            "Reload the latest case and try again."
                        ),
                    )
                    return redirect(
                        "cases:case_update",
                        case_id=case.pk,
                    )

            updated_case = get_accessible_case_or_404(
                user=request.user,
                case_id=case.pk,
            )

            messages.success(
                request,
                (
                    f"Case {updated_case.case_number} was "
                    "updated successfully."
                ),
            )
            return redirect(
                "cases:case_detail",
                case_id=updated_case.pk,
            )

    else:
        form = CaseForm(
            instance=case,
            current_user=request.user,
        )
        edit_version = build_case_edit_version(
            case
        )

    context = get_common_case_context(
        request
    )

    context.update({
        "page_title": "Update Case",
        "page_subtitle": case.case_number,
        "case": case,
        "form": form,
        "submit_label": "Save Changes",
        "cancel_url_name": "cases:case_detail",
        "edit_version": edit_version,
    })

    return render(
        request,
        "cases/case_update.html",
        context,
    )


# ==========================================================
# Investigator Assignment
# ==========================================================

@login_required
@require_POST
def case_assign(
    request: HttpRequest,
    case_id: Any,
) -> HttpResponse:
    """
    Assign/reassign an investigator with an atomic compare-and-set update.
    """

    case = get_accessible_case_or_404(
        user=request.user,
        case_id=case_id,
    )

    if not can_assign_case(
        request.user,
        case,
    ):
        if case.status == Case.Status.ARCHIVED:
            messages.warning(
                request,
                (
                    "Archived cases cannot be assigned. "
                    "Restore the case first."
                ),
            )
            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

        raise PermissionDenied(
            "You do not have permission to assign cases."
        )

    expected_updated_date = case.updated_date
    expected_status = case.status
    expected_is_active = case.is_active

    form = CaseAssignmentForm(
        request.POST,
        instance=case,
    )

    if form.is_valid():
        candidate = form.save(
            commit=False
        )
        candidate.full_clean()

        update_time = timezone.now()

        with transaction.atomic():
            updated_rows = (
                Case.objects
                .filter(
                    pk=case.pk,
                    updated_date=expected_updated_date,
                    status=expected_status,
                    is_active=expected_is_active,
                )
                .update(
                    assigned_investigator_id=(
                        candidate.assigned_investigator_id
                    ),
                    status=candidate.status,
                    is_active=candidate.is_active,
                    updated_date=update_time,
                )
            )

            if updated_rows != 1:
                messages.warning(
                    request,
                    (
                        "This case changed while the assignment was being "
                        "saved. The assignment was not applied. Refresh and "
                        "try again."
                    ),
                )
                return redirect(
                    "cases:case_detail",
                    case_id=case.pk,
                )

        assigned_case = get_accessible_case_or_404(
            user=request.user,
            case_id=case.pk,
        )

        messages.success(
            request,
            (
                f"Case {assigned_case.case_number} was assigned "
                f"to {assigned_case.assigned_investigator.full_name}."
            ),
        )
    else:
        error_message = next(
            iter(form.errors.values()),
            ["Unable to assign the case."],
        )[0]

        messages.error(
            request,
            str(error_message),
        )

    return redirect(
        "cases:case_detail",
        case_id=case.pk,
    )


# ==========================================================
# Status Update
# ==========================================================

@login_required
@require_POST
def case_status_update(
    request: HttpRequest,
    case_id: Any,
) -> HttpResponse:
    """
    Update only normal workflow states with an atomic compare-and-set write.

    ARCHIVED cannot be selected here; the dedicated archive workflow preserves
    archive metadata and confirmation.
    """

    case = get_accessible_case_or_404(
        user=request.user,
        case_id=case_id,
    )

    if not can_change_case_status(
        request.user,
        case,
    ):
        if case.status == Case.Status.ARCHIVED:
            messages.warning(
                request,
                (
                    "Archived cases cannot have their status changed. "
                    "Restore the case first."
                ),
            )
            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

        raise PermissionDenied(
            "You do not have permission to change this case status."
        )

    expected_updated_date = case.updated_date
    expected_status = case.status
    expected_is_active = case.is_active

    form = CaseStatusForm(
        request.POST,
        instance=case,
        current_user=request.user,
    )

    if not form.is_valid():
        error_message = next(
            iter(form.errors.values()),
            ["Unable to update the case status."],
        )[0]

        messages.error(
            request,
            str(error_message),
        )
        return redirect(
            "cases:case_detail",
            case_id=case.pk,
        )

    selected_status = form.cleaned_data[
        "status"
    ]

    # ModelForm validation writes cleaned values onto ``instance``. Because
    # the form uses ``case`` as its instance, ``case.status`` may already hold
    # selected_status here even though the database still contains the old
    # status. Compare against the pre-form database snapshot instead.
    if selected_status == expected_status:
        messages.info(
            request,
            (
                "Case status is already "
                f"{case.get_status_display()}."
            ),
        )
        return redirect(
            "cases:case_detail",
            case_id=case.pk,
        )

    candidate = form.save(
        commit=False
    )
    candidate.is_active = True
    candidate.full_clean()

    update_time = timezone.now()

    with transaction.atomic():
        updated_rows = (
            Case.objects
            .filter(
                pk=case.pk,
                updated_date=expected_updated_date,
                status=expected_status,
                is_active=expected_is_active,
            )
            .update(
                status=selected_status,
                is_active=True,
                updated_date=update_time,
            )
        )

        if updated_rows != 1:
            messages.warning(
                request,
                (
                    "This case changed while the status update was being "
                    "processed. The status was not changed. Refresh and "
                    "try again."
                ),
            )
            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

    updated_case = get_accessible_case_or_404(
        user=request.user,
        case_id=case.pk,
    )

    messages.success(
        request,
        (
            "Case status changed to "
            f"{updated_case.get_status_display()}."
        ),
    )

    return redirect(
        "cases:case_detail",
        case_id=updated_case.pk,
    )


# ==========================================================
# Case Archive
# ==========================================================

@login_required
@require_http_methods([
    "GET",
    "POST",
])
def case_archive(
    request: HttpRequest,
    case_id: Any,
) -> HttpResponse:
    """
    Archive a case with an atomic active -> archived transition.
    """

    case = get_accessible_case_or_404(
        user=request.user,
        case_id=case_id,
    )

    if not can_archive_case(
        request.user,
        case,
    ):
        if case.status == Case.Status.ARCHIVED:
            messages.info(
                request,
                "This case is already archived.",
            )
            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

        raise PermissionDenied(
            "You do not have permission to archive cases."
        )

    if request.method == "POST":
        form = CaseArchiveForm(
            request.POST
        )

        if form.is_valid():
            archive_reason = form.cleaned_data[
                "reason"
            ]

            expected_updated_date = case.updated_date
            expected_status = case.status
            archived_at = timezone.now()

            candidate = case
            candidate.pre_archive_status = expected_status
            candidate.archive_reason = archive_reason
            candidate.archived_at = archived_at
            candidate.archived_by = request.user
            candidate.status = Case.Status.ARCHIVED
            candidate.is_active = False
            candidate.full_clean()

            with transaction.atomic():
                updated_rows = (
                    Case.objects
                    .filter(
                        pk=case.pk,
                        updated_date=expected_updated_date,
                        status=expected_status,
                        is_active=True,
                    )
                    .update(
                        pre_archive_status=expected_status,
                        archive_reason=archive_reason,
                        archived_at=archived_at,
                        archived_by_id=request.user.pk,
                        status=Case.Status.ARCHIVED,
                        is_active=False,
                        updated_date=archived_at,
                    )
                )

                if updated_rows != 1:
                    messages.warning(
                        request,
                        (
                            "This case changed while the archive action was "
                            "being processed. It was not archived. Refresh "
                            "and try again."
                        ),
                    )
                    return redirect(
                        "cases:case_detail",
                        case_id=case.pk,
                    )

            messages.success(
                request,
                (
                    f"Case {case.case_number} was archived "
                    "successfully."
                ),
            )
            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

        messages.error(
            request,
            (
                "The case could not be archived. Confirm the action and "
                "enter a meaningful archive reason."
            ),
        )

    else:
        form = CaseArchiveForm()

    context = get_common_case_context(
        request
    )

    context.update({
        "page_title": "Archive Case",
        "page_subtitle": case.case_number,
        "case": case,
        "form": form,
    })

    return render(
        request,
        "cases/case_archive.html",
        context,
    )


# ==========================================================
# Case Restore
# ==========================================================

@case_role_required(
    ROLE_ADMINISTRATOR,
    ROLE_CYBER_OFFICER,
)
@require_POST
def case_restore(
    request: HttpRequest,
    case_id: Any,
) -> HttpResponse:
    """
    Restore an archived case to its pre-archive status with an atomic
    archived -> active transition.
    """

    form = CaseRestoreForm(
        request.POST
    )

    if not form.is_valid():
        messages.error(
            request,
            "Confirm the restore action before continuing.",
        )
        return redirect(
            "cases:case_detail",
            case_id=case_id,
        )

    case = get_accessible_case_or_404(
        user=request.user,
        case_id=case_id,
    )

    if not can_restore_case(
        request.user,
        case,
    ):
        if case.is_active:
            messages.info(
                request,
                "This case is already active.",
            )
            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

        raise PermissionDenied(
            "You do not have permission to restore this case."
        )

    expected_updated_date = case.updated_date
    target_status = case.restore_status
    restore_time = timezone.now()

    candidate = case
    candidate.status = target_status
    candidate.is_active = True
    candidate.full_clean()

    with transaction.atomic():
        updated_rows = (
            Case.objects
            .filter(
                pk=case.pk,
                updated_date=expected_updated_date,
                status=Case.Status.ARCHIVED,
                is_active=False,
            )
            .update(
                status=target_status,
                is_active=True,
                updated_date=restore_time,
            )
        )

        if updated_rows != 1:
            current = get_accessible_case_or_404(
                user=request.user,
                case_id=case.pk,
            )

            if current.is_active:
                messages.info(
                    request,
                    "This case is already active.",
                )
            else:
                messages.warning(
                    request,
                    (
                        "This case changed while the restore action was being "
                        "processed. It was not restored. Refresh and try again."
                    ),
                )

            return redirect(
                "cases:case_detail",
                case_id=case.pk,
            )

    restored_case = get_accessible_case_or_404(
        user=request.user,
        case_id=case.pk,
    )

    messages.success(
        request,
        (
            f"Case {restored_case.case_number} was restored to "
            f"{restored_case.get_status_display()}."
        ),
    )

    return redirect(
        "cases:case_detail",
        case_id=restored_case.pk,
    )
