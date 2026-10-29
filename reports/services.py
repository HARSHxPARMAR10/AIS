"""
AIDEX Reports Services

Transactional service layer for the investigation-report workflow.

Responsibilities
----------------
- Role-aware report access
- Report creation/update audit events
- Submit / review / approve / reject / publish workflow
- Controlled archive / restore
- Revision creation with evidence/AI reference copying
- Report file integrity verification
- Download audit logging

Views should stay thin and call these services instead of mutating Report
workflow fields directly.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.base import ContentFile
from django.db import IntegrityError, OperationalError, transaction
from django.db.models import Max, Q, QuerySet
from django.utils import timezone

from cases.models import Case

from .models import Report, ReportAuditLog


# ============================================================================
# Roles
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
# Exceptions
# ============================================================================

class ReportServiceError(Exception):
    """Base error for professional report workflow operations."""


class ReportStateError(ReportServiceError):
    """Raised when a workflow action is invalid for the current status."""


class ReportAccessError(ReportServiceError):
    """Raised when a user is not allowed to perform an action."""


class ReportIntegrityError(ReportServiceError):
    """Raised when report-file integrity cannot be verified safely."""


class ReportRevisionError(ReportServiceError):
    """Raised when a new report revision cannot be created."""


# ============================================================================
# DTOs
# ============================================================================

@dataclass(slots=True)
class ReportIntegrityResult:
    """
    Result of an explicit report-file SHA-256 verification.
    """

    checked: bool
    matched: bool
    stored_hash: str = ""
    calculated_hash: str = ""
    file_name: str = ""
    error: str = ""


# ============================================================================
# Generic Helpers
# ============================================================================

def normalize_role(
    role_value: Any,
) -> str:
    normalized = (
        str(role_value or "")
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return ROLE_ALIASES.get(
        normalized,
        normalized,
    )


def get_user_role(
    user: Any,
) -> str:
    if getattr(
        user,
        "is_superuser",
        False,
    ):
        return ROLE_ADMINISTRATOR

    return normalize_role(
        getattr(
            user,
            "role",
            "",
        )
    )


def user_has_role(
    user: Any,
    *roles: str,
) -> bool:
    current_role = get_user_role(
        user
    )

    return current_role in {
        normalize_role(role)
        for role in roles
    }


def normalize_text(
    value: Any,
) -> str:
    text = (
        str(value or "")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )

    return "\n".join(
        line.rstrip()
        for line in text.splitlines()
    ).strip()


def truncate_text(
    value: Any,
    maximum_length: int,
) -> str:
    text = normalize_text(
        value
    )

    if len(text) <= maximum_length:
        return text

    return text[:maximum_length]


def make_metadata_safe(
    value: Any,
) -> Any:
    """
    Convert lightweight metadata into JSONField-safe values.
    """

    if value is None or isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):
        return value

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): make_metadata_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            make_metadata_safe(item)
            for item in value
        ]

    return str(value)


def get_actor_label(
    actor: Any,
) -> str:
    if actor is None:
        return "System"

    full_name = normalize_text(
        getattr(
            actor,
            "full_name",
            "",
        )
    )

    if full_name:
        return full_name

    username = normalize_text(
        getattr(
            actor,
            "username",
            "",
        )
    )

    return username or "Unknown User"


# ============================================================================
# Query / Access Layer
# ============================================================================

def get_accessible_reports(
    user: Any,
    *,
    include_archived: bool = True,
) -> QuerySet[Report]:
    """
    Return reports visible to the current AIDEX user.

    Administrator / Cyber Officer:
        May view all reports.

    Investigator:
        May view reports for cases they created/are assigned to, plus reports
        they generated themselves.
    """

    queryset = (
        Report.objects
        .select_related(
            "case",
            "case__created_by",
            "case__assigned_investigator",
            "generated_by",
            "reviewed_by",
            "approved_by",
            "published_by",
            "archived_by",
            "supersedes",
        )
        .prefetch_related(
            "included_evidence",
            "included_analyses",
        )
    )

    if not getattr(
        user,
        "is_authenticated",
        False,
    ):
        return queryset.none()

    role = get_user_role(
        user
    )

    if role in {
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    }:
        accessible = queryset

    elif role == ROLE_INVESTIGATOR:
        accessible = (
            queryset
            .filter(
                Q(case__created_by=user)
                | Q(
                    case__assigned_investigator=user
                )
                | Q(generated_by=user)
            )
            .distinct()
        )

    else:
        return queryset.none()

    if not include_archived:
        accessible = accessible.filter(
            is_active=True
        ).exclude(
            status=Report.Status.ARCHIVED
        )

    return accessible


def can_create_report(
    user: Any,
) -> bool:
    return user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_INVESTIGATOR,
        ROLE_CYBER_OFFICER,
    )


def can_edit_report(
    user: Any,
    report: Report,
) -> bool:
    if (
        not report.is_active
        or not report.can_be_edited
    ):
        return False

    if user_has_role(
        user,
        ROLE_ADMINISTRATOR,
    ):
        return True

    if user_has_role(
        user,
        ROLE_CYBER_OFFICER,
    ):
        return True

    if user_has_role(
        user,
        ROLE_INVESTIGATOR,
    ):
        return bool(
            report.generated_by_id
            == getattr(
                user,
                "pk",
                None,
            )
            or report.case.assigned_investigator_id
            == getattr(
                user,
                "pk",
                None,
            )
        )

    return False


def can_submit_report(
    user: Any,
    report: Report,
) -> bool:
    if not can_edit_report(
        user,
        report,
    ):
        return False

    return report.status in {
        Report.Status.DRAFT,
        Report.Status.REJECTED,
    }


def can_review_report(
    user: Any,
    report: Report,
) -> bool:
    if (
        not report.is_active
        or report.status
        != Report.Status.UNDER_REVIEW
    ):
        return False

    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    # Separation of duties: the author should not formally review their own
    # report. Administrator may still resolve workflow by assigning/reviewing
    # through another account.
    return (
        report.generated_by_id
        != getattr(
            user,
            "pk",
            None,
        )
    )


def can_approve_report(
    user: Any,
    report: Report,
) -> bool:
    if (
        not report.is_active
        or report.status
        != Report.Status.UNDER_REVIEW
    ):
        return False

    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
    ):
        return False

    if (
        report.generated_by_id
        == getattr(
            user,
            "pk",
            None,
        )
    ):
        return False

    return bool(
        report.reviewed_by_id
        and report.reviewed_date
    )


def can_reject_report(
    user: Any,
    report: Report,
) -> bool:
    return can_review_report(
        user,
        report,
    )


def can_publish_report(
    user: Any,
    report: Report,
) -> bool:
    return bool(
        user_has_role(
            user,
            ROLE_ADMINISTRATOR,
        )
        and report.is_active
        and report.status
        == Report.Status.APPROVED
        and report.can_be_published
    )


def can_archive_report(
    user: Any,
    report: Report,
) -> bool:
    return bool(
        user_has_role(
            user,
            ROLE_ADMINISTRATOR,
            ROLE_CYBER_OFFICER,
        )
        and report.is_active
        and report.status
        != Report.Status.ARCHIVED
    )


def can_restore_report(
    user: Any,
    report: Report,
) -> bool:
    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
    ):
        return False

    if (
        report.status
        != Report.Status.ARCHIVED
        or report.is_active
    ):
        return False

    case = report.case

    return bool(
        case.is_active
        and case.status
        != Case.Status.ARCHIVED
    )


def can_create_revision(
    user: Any,
    report: Report,
) -> bool:
    if not user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_INVESTIGATOR,
        ROLE_CYBER_OFFICER,
    ):
        return False

    if report.status == Report.Status.ARCHIVED:
        return False

    if not report.case.is_active:
        return False

    if (
        report.case.status
        == Case.Status.ARCHIVED
    ):
        return False

    if user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    ):
        return True

    return bool(
        report.generated_by_id
        == getattr(
            user,
            "pk",
            None,
        )
        or report.case.assigned_investigator_id
        == getattr(
            user,
            "pk",
            None,
        )
    )


def can_download_report(
    user: Any,
    report: Report,
) -> bool:
    if not report.report_file:
        return False

    return get_accessible_reports(
        user
    ).filter(
        pk=report.pk
    ).exists()


def can_view_report_audit(
    user: Any,
    report: Report,
) -> bool:
    if not get_accessible_reports(
        user
    ).filter(
        pk=report.pk
    ).exists():
        return False

    return user_has_role(
        user,
        ROLE_ADMINISTRATOR,
        ROLE_CYBER_OFFICER,
    )


# ============================================================================
# Audit Helpers
# ============================================================================

def create_report_audit_log(
    report: Report,
    event_type: str,
    message: str,
    *,
    actor: Any = None,
    from_status: str = "",
    to_status: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> ReportAuditLog:
    """
    Create one immutable-style report audit event.
    """

    return ReportAuditLog.objects.create(
        report=report,
        event_type=event_type,
        actor=(
            actor
            if getattr(
                actor,
                "is_authenticated",
                False,
            )
            else None
        ),
        message=truncate_text(
            message,
            8_000,
        ),
        from_status=from_status,
        to_status=to_status,
        metadata=make_metadata_safe(
            metadata
            or {}
        ),
    )


def build_report_audit_snapshot(
    report: Report,
) -> dict[str, Any]:
    """
    Return a compact snapshot for lifecycle audit metadata.
    """

    return {
        "report_number": (
            report.report_number
        ),
        "report_title": (
            report.report_title
        ),
        "report_type": (
            report.report_type
        ),
        "version": (
            report.version
        ),
        "case_id": str(
            report.case_id
        ),
        "case_number": (
            report.case.case_number
        ),
        "status": (
            report.status
        ),
        "is_active": (
            report.is_active
        ),
        "is_confidential": (
            report.is_confidential
        ),
        "has_file": bool(
            report.report_file
        ),
        "file_sha256": (
            report.file_sha256
        ),
        "included_evidence_count": (
            report.included_evidence.count()
        ),
        "included_analysis_count": (
            report.included_analyses.count()
        ),
    }


def record_report_created(
    report: Report,
    *,
    actor: Any = None,
) -> ReportAuditLog:
    return create_report_audit_log(
        report,
        ReportAuditLog.EventType.CREATED,
        "Investigation report created.",
        actor=actor,
        to_status=report.status,
        metadata=build_report_audit_snapshot(
            report
        ),
    )


def record_report_updated(
    report: Report,
    *,
    actor: Any = None,
    changed_fields: list[str] | tuple[str, ...] | None = None,
) -> ReportAuditLog:
    return create_report_audit_log(
        report,
        ReportAuditLog.EventType.UPDATED,
        "Investigation report content updated.",
        actor=actor,
        from_status=report.status,
        to_status=report.status,
        metadata={
            "changed_fields": list(
                changed_fields
                or []
            ),
            "snapshot": (
                build_report_audit_snapshot(
                    report
                )
            ),
        },
    )


# ============================================================================
# Locking Helper
# ============================================================================

def get_locked_report(
    report_id: Any,
) -> Report:
    """
    Reload one report under a transaction row lock.
    """

    return (
        Report.objects
        .select_for_update()
        .select_related(
            "case",
            "case__created_by",
            "case__assigned_investigator",
            "generated_by",
            "reviewed_by",
            "approved_by",
            "published_by",
            "archived_by",
            "supersedes",
        )
        .get(
            pk=report_id
        )
    )


def get_current_report(
    report_id: Any,
) -> Report:
    """
    Reload one report with the relations required by workflow permission
    checks.

    Workflow mutations use an atomic compare-and-set UPDATE below rather than
    relying on select_for_update(), because SQLite ignores row-level
    select_for_update() locking.
    """

    return (
        Report.objects
        .select_related(
            "case",
            "case__created_by",
            "case__assigned_investigator",
            "generated_by",
            "reviewed_by",
            "approved_by",
            "published_by",
            "archived_by",
            "supersedes",
        )
        .get(
            pk=report_id
        )
    )


def atomic_report_workflow_update(
    report: Report,
    *,
    expected_status: str,
    expected_updated_date: Any,
    expected_is_active: bool,
    updates: Mapping[str, Any],
    action_label: str,
) -> Report:
    """
    Apply one report workflow mutation with optimistic concurrency control.

    The UPDATE succeeds only when status, active-state and updated_date still
    match the snapshot used for validation. Therefore two simultaneous
    Review/Approve/Reject/Publish/Archive/Restore requests cannot silently
    overwrite one another, including when AIDEX uses SQLite.
    """

    update_time = timezone.now()

    values = dict(
        updates
    )
    values["updated_date"] = update_time

    try:
        updated_rows = (
            Report.objects
            .filter(
                pk=report.pk,
                status=expected_status,
                is_active=expected_is_active,
                updated_date=expected_updated_date,
            )
            .update(
                **values
            )
        )
    except OperationalError as exc:
        raise ReportStateError(
            (
                f"The report is being updated by another request. "
                f"{action_label} was not applied. Refresh and try again."
            )
        ) from exc

    if updated_rows != 1:
        raise ReportStateError(
            (
                f"The report changed while {action_label.lower()} was being "
                "processed. Your action was not applied. Refresh the report "
                "and try again."
            )
        )

    return get_current_report(
        report.pk
    )


# ============================================================================
# Workflow Actions
# ============================================================================

def submit_report_for_review(
    report: Report,
    *,
    actor: Any,
    submission_note: str = "",
) -> Report:
    """
    Move Draft/Rejected -> Under Review safely.

    The transition uses status + updated_date as an optimistic concurrency
    token, so a simultaneous edit or lifecycle action cannot be overwritten.
    """

    with transaction.atomic():
        current = get_current_report(
            report.pk
        )

        if not can_submit_report(
            actor,
            current,
        ):
            raise ReportAccessError(
                (
                    "You cannot submit this report for review "
                    "in its current state."
                )
            )

        if not current.case.is_active:
            raise ReportStateError(
                "Reports for inactive cases cannot be submitted."
            )

        if current.case.status == Case.Status.ARCHIVED:
            raise ReportStateError(
                "Reports for archived cases cannot be submitted."
            )

        previous_status = current.status
        expected_updated_date = current.updated_date

        candidate = current
        candidate.status = Report.Status.UNDER_REVIEW
        candidate.reviewed_by = None
        candidate.reviewed_date = None
        candidate.review_notes = ""
        candidate.approved_by = None
        candidate.approved_date = None
        candidate.approval_notes = ""
        candidate.rejection_reason = ""
        candidate.published_by = None
        candidate.published_date = None
        candidate.full_clean()

        current = atomic_report_workflow_update(
            current,
            expected_status=previous_status,
            expected_updated_date=expected_updated_date,
            expected_is_active=True,
            updates={
                "status": Report.Status.UNDER_REVIEW,
                "reviewed_by": None,
                "reviewed_date": None,
                "review_notes": "",
                "approved_by": None,
                "approved_date": None,
                "approval_notes": "",
                "rejection_reason": "",
                "published_by": None,
                "published_date": None,
            },
            action_label="Submit for Review",
        )

        create_report_audit_log(
            current,
            ReportAuditLog.EventType.SUBMITTED,
            "Report submitted for formal review.",
            actor=actor,
            from_status=previous_status,
            to_status=current.status,
            metadata={
                "submission_note": truncate_text(
                    submission_note,
                    1_500,
                ),
                "transition_strategy": (
                    "atomic_compare_and_set"
                ),
            },
        )

        return current


def record_report_review(
    report: Report,
    *,
    actor: Any,
    review_notes: str,
) -> Report:
    """
    Record formal reviewer observations without allowing stale-review
    overwrite.

    If another reviewer or workflow action changes the report first, this
    request is rejected instead of replacing the newer data.
    """

    notes = normalize_text(
        review_notes
    )

    if len(notes) < 10:
        raise ReportStateError(
            "Meaningful review notes are required."
        )

    with transaction.atomic():
        current = get_current_report(
            report.pk
        )

        if not can_review_report(
            actor,
            current,
        ):
            raise ReportAccessError(
                "You cannot review this report."
            )

        expected_updated_date = current.updated_date
        reviewed_date = timezone.now()

        candidate = current
        candidate.reviewed_by = actor
        candidate.reviewed_date = reviewed_date
        candidate.review_notes = notes
        candidate.full_clean()

        current = atomic_report_workflow_update(
            current,
            expected_status=Report.Status.UNDER_REVIEW,
            expected_updated_date=expected_updated_date,
            expected_is_active=True,
            updates={
                "reviewed_by_id": actor.pk,
                "reviewed_date": reviewed_date,
                "review_notes": notes,
            },
            action_label="Formal Review",
        )

        create_report_audit_log(
            current,
            ReportAuditLog.EventType.REVIEWED,
            "Formal report review completed.",
            actor=actor,
            from_status=current.status,
            to_status=current.status,
            metadata={
                "review_notes": truncate_text(
                    notes,
                    2_000,
                ),
                "transition_strategy": (
                    "atomic_compare_and_set"
                ),
            },
        )

        return current


def approve_report(
    report: Report,
    *,
    actor: Any,
    approval_notes: str = "",
) -> Report:
    """
    Move Under Review -> Approved with an atomic state transition.
    """

    notes = normalize_text(
        approval_notes
    )

    with transaction.atomic():
        current = get_current_report(
            report.pk
        )

        if not can_approve_report(
            actor,
            current,
        ):
            raise ReportAccessError(
                (
                    "This report cannot be approved. It must be "
                    "Under Review with a completed formal review, and "
                    "approval requires an Administrator who is not the author."
                )
            )

        previous_status = current.status
        expected_updated_date = current.updated_date
        approved_date = timezone.now()

        candidate = current
        candidate.status = Report.Status.APPROVED
        candidate.approved_by = actor
        candidate.approved_date = approved_date
        candidate.approval_notes = notes
        candidate.rejection_reason = ""
        candidate.full_clean()

        current = atomic_report_workflow_update(
            current,
            expected_status=previous_status,
            expected_updated_date=expected_updated_date,
            expected_is_active=True,
            updates={
                "status": Report.Status.APPROVED,
                "approved_by_id": actor.pk,
                "approved_date": approved_date,
                "approval_notes": notes,
                "rejection_reason": "",
            },
            action_label="Approval",
        )

        create_report_audit_log(
            current,
            ReportAuditLog.EventType.APPROVED,
            "Investigation report approved.",
            actor=actor,
            from_status=previous_status,
            to_status=current.status,
            metadata={
                "approval_notes": truncate_text(
                    notes,
                    2_000,
                ),
                "reviewed_by_id": (
                    str(current.reviewed_by_id)
                    if current.reviewed_by_id
                    else ""
                ),
                "transition_strategy": (
                    "atomic_compare_and_set"
                ),
            },
        )

        return current


def reject_report(
    report: Report,
    *,
    actor: Any,
    rejection_reason: str,
) -> Report:
    """
    Move Under Review -> Rejected with an atomic state transition.
    """

    reason = normalize_text(
        rejection_reason
    )

    if len(reason) < 10:
        raise ReportStateError(
            "A meaningful rejection reason is required."
        )

    with transaction.atomic():
        current = get_current_report(
            report.pk
        )

        if not can_reject_report(
            actor,
            current,
        ):
            raise ReportAccessError(
                "You cannot reject this report."
            )

        previous_status = current.status
        expected_updated_date = current.updated_date
        reviewed_date = timezone.now()
        review_notes = normalize_text(
            current.review_notes
        ) or "Report rejected during formal review."

        candidate = current
        candidate.reviewed_by = actor
        candidate.reviewed_date = reviewed_date
        candidate.review_notes = review_notes
        candidate.rejection_reason = reason
        candidate.approved_by = None
        candidate.approved_date = None
        candidate.approval_notes = ""
        candidate.published_by = None
        candidate.published_date = None
        candidate.status = Report.Status.REJECTED
        candidate.full_clean()

        current = atomic_report_workflow_update(
            current,
            expected_status=previous_status,
            expected_updated_date=expected_updated_date,
            expected_is_active=True,
            updates={
                "reviewed_by_id": actor.pk,
                "reviewed_date": reviewed_date,
                "review_notes": review_notes,
                "rejection_reason": reason,
                "approved_by": None,
                "approved_date": None,
                "approval_notes": "",
                "published_by": None,
                "published_date": None,
                "status": Report.Status.REJECTED,
            },
            action_label="Rejection",
        )

        create_report_audit_log(
            current,
            ReportAuditLog.EventType.REJECTED,
            "Investigation report rejected for revision.",
            actor=actor,
            from_status=previous_status,
            to_status=current.status,
            metadata={
                "rejection_reason": truncate_text(
                    reason,
                    2_000,
                ),
                "transition_strategy": (
                    "atomic_compare_and_set"
                ),
            },
        )

        return current


def publish_report(
    report: Report,
    *,
    actor: Any,
    publication_note: str = "",
) -> Report:
    """
    Move Approved -> Published with an atomic state transition.
    """

    with transaction.atomic():
        current = get_current_report(
            report.pk
        )

        if not can_publish_report(
            actor,
            current,
        ):
            raise ReportAccessError(
                "Only an eligible approved report can be published."
            )

        if not current.report_file:
            raise ReportStateError(
                "Generate or upload the final PDF before publication."
            )

        source_name = (
            current.original_filename
            or current.report_file.name
            or ""
        )

        if Path(source_name).suffix.lower() != ".pdf":
            raise ReportStateError(
                "Published reports must use PDF format."
            )

        # Final publication gate: old/tampered report records must never
        # publish raw or unreviewed AI output. Form-level filtering protects
        # normal edits, but publication re-validates persisted M2M references
        # because existing records may predate that form rule.
        invalid_analyses = (
            current.included_analyses
            .exclude(
                is_active=True,
                status="COMPLETED",
                evidence__is_active=True,
                evidence__case_id=current.case_id,
                reviewed_by__isnull=False,
                reviewed_at__isnull=False,
            )
        )

        if invalid_analyses.exists():
            raise ReportStateError(
                (
                    "This report contains an AI analysis that is inactive, "
                    "incomplete, belongs to another case, or has not completed "
                    "human review. Remove or review it before publication."
                )
            )

        previous_status = current.status
        expected_updated_date = current.updated_date
        published_date = timezone.now()

        candidate = current
        candidate.status = Report.Status.PUBLISHED
        candidate.published_by = actor
        candidate.published_date = published_date
        candidate.full_clean()

        current = atomic_report_workflow_update(
            current,
            expected_status=previous_status,
            expected_updated_date=expected_updated_date,
            expected_is_active=True,
            updates={
                "status": Report.Status.PUBLISHED,
                "published_by_id": actor.pk,
                "published_date": published_date,
            },
            action_label="Publication",
        )

        create_report_audit_log(
            current,
            ReportAuditLog.EventType.PUBLISHED,
            "Approved investigation report published.",
            actor=actor,
            from_status=previous_status,
            to_status=current.status,
            metadata={
                "publication_note": truncate_text(
                    publication_note,
                    2_000,
                ),
                "file_sha256": current.file_sha256,
                "transition_strategy": (
                    "atomic_compare_and_set"
                ),
            },
        )

        return current


def archive_report(
    report: Report,
    *,
    actor: Any,
    reason: str,
) -> Report:
    """
    Archive a report without deleting its history.

    The active -> archived transition is atomic, preventing simultaneous
    lifecycle actions from producing duplicate audit events or stale state.
    """

    archive_reason = normalize_text(
        reason
    )

    if len(archive_reason) < 10:
        raise ReportStateError(
            "A meaningful archive reason is required."
        )

    with transaction.atomic():
        current = get_current_report(
            report.pk
        )

        if (
            current.status == Report.Status.ARCHIVED
            or not current.is_active
        ):
            return current

        if not can_archive_report(
            actor,
            current,
        ):
            raise ReportAccessError(
                "You cannot archive this report."
            )

        previous_status = current.status
        expected_updated_date = current.updated_date
        archived_at = timezone.now()

        candidate = current
        candidate.pre_archive_status = previous_status
        candidate.status = Report.Status.ARCHIVED
        candidate.archive_reason = archive_reason
        candidate.archived_by = actor
        candidate.archived_at = archived_at
        candidate.is_active = False
        candidate.full_clean()

        current = atomic_report_workflow_update(
            current,
            expected_status=previous_status,
            expected_updated_date=expected_updated_date,
            expected_is_active=True,
            updates={
                "status": Report.Status.ARCHIVED,
                "pre_archive_status": previous_status,
                "archive_reason": archive_reason,
                "archived_by_id": actor.pk,
                "archived_at": archived_at,
                "is_active": False,
            },
            action_label="Archive",
        )

        create_report_audit_log(
            current,
            ReportAuditLog.EventType.ARCHIVED,
            "Investigation report archived.",
            actor=actor,
            from_status=previous_status,
            to_status=current.status,
            metadata={
                "archive_reason": truncate_text(
                    archive_reason,
                    2_000,
                ),
                "pre_archive_status": (
                    current.pre_archive_status
                ),
                "transition_strategy": (
                    "atomic_compare_and_set"
                ),
            },
        )

        return current


def restore_report(
    report: Report,
    *,
    actor: Any,
) -> Report:
    """
    Restore an archived report to its recorded pre-archive status safely.
    """

    with transaction.atomic():
        current = get_current_report(
            report.pk
        )

        if (
            current.status != Report.Status.ARCHIVED
            and current.is_active
        ):
            return current

        if not can_restore_report(
            actor,
            current,
        ):
            if (
                not current.case.is_active
                or current.case.status == Case.Status.ARCHIVED
            ):
                raise ReportStateError(
                    (
                        "Restore the linked case before restoring "
                        "this report."
                    )
                )

            raise ReportAccessError(
                "You cannot restore this report."
            )

        previous_status = current.status
        target_status = current.restore_status
        expected_updated_date = current.updated_date

        candidate = current
        candidate.status = target_status
        candidate.is_active = True
        candidate.full_clean()

        current = atomic_report_workflow_update(
            current,
            expected_status=Report.Status.ARCHIVED,
            expected_updated_date=expected_updated_date,
            expected_is_active=False,
            updates={
                "status": target_status,
                "is_active": True,
            },
            action_label="Restore",
        )

        create_report_audit_log(
            current,
            ReportAuditLog.EventType.RESTORED,
            "Archived investigation report restored.",
            actor=actor,
            from_status=previous_status,
            to_status=current.status,
            metadata={
                "restored_to_status": target_status,
                "latest_archive_reason": current.archive_reason,
                "latest_archived_at": (
                    current.archived_at.isoformat()
                    if current.archived_at
                    else ""
                ),
                "transition_strategy": (
                    "atomic_compare_and_set"
                ),
            },
        )

        return current



# ============================================================================
# Revision Workflow
# ============================================================================

def _copy_report_file_to_revision(
    *,
    source: Report,
    target: Report,
) -> None:
    """
    Copy the existing stored file into a new FieldFile object.

    The new report receives a new storage path and its own integrity metadata.
    """

    if not source.report_file:
        return

    try:
        source.report_file.open(
            "rb"
        )

        file_bytes = (
            source.report_file.read()
        )

    except (
        FileNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        raise ReportRevisionError(
            (
                "The source report file could not be read "
                "for revision copying."
            )
        ) from exc

    finally:
        try:
            source.report_file.close()
        except Exception:
            pass

    filename = (
        source.original_filename
        or Path(
            source.report_file.name
        ).name
        or "report.pdf"
    )

    target.report_file.save(
        filename,
        ContentFile(
            file_bytes
        ),
        save=False,
    )


def create_report_revision(
    report: Report,
    *,
    actor: Any,
    revision_reason: str,
    revision_title: str = "",
    copy_report_file: bool = False,
) -> Report:
    """
    Clone a report into a new Draft revision.

    The new revision:
    - belongs to the same case and report type;
    - receives the next version number;
    - supersedes the selected source report;
    - copies narrative sections and selected evidence/AI references;
    - does not inherit reviewer/approver/publisher lifecycle attribution;
    - optionally copies the file to a new storage object.
    """

    reason = normalize_text(
        revision_reason
    )

    if len(reason) < 10:
        raise ReportRevisionError(
            "A meaningful revision reason is required."
        )

    with transaction.atomic():
        source = get_locked_report(
            report.pk
        )

        if not can_create_revision(
            actor,
            source,
        ):
            raise ReportAccessError(
                "You cannot create a revision of this report."
            )

        # Lock existing same-lineage rows where supported and calculate the
        # next version from current database state.
        lineage_queryset = (
            Report.objects
            .select_for_update()
            .filter(
                case=source.case,
                report_type=source.report_type,
                report_title=source.report_title,
            )
        )

        list(
            lineage_queryset.values_list(
                "pk",
                flat=True,
            )
        )

        maximum_version = (
            lineage_queryset.aggregate(
                maximum=Max(
                    "version"
                )
            )[
                "maximum"
            ]
            or source.version
        )

        next_version = (
            int(
                maximum_version
            )
            + 1
        )

        new_title = (
            normalize_text(
                revision_title
            )
            or source.report_title
        )

        revision = Report(
            case=source.case,
            report_title=new_title,
            report_type=source.report_type,
            version=next_version,
            supersedes=source,
            summary=source.summary,
            findings=source.findings,
            evidence_summary=(
                source.evidence_summary
            ),
            ai_analysis_summary=(
                source.ai_analysis_summary
            ),
            conclusion=source.conclusion,
            recommendations=(
                source.recommendations
            ),
            review_notes="",
            approval_notes="",
            rejection_reason="",
            generated_by=actor,
            status=Report.Status.DRAFT,
            is_confidential=(
                source.is_confidential
            ),
            is_active=True,
        )

        if copy_report_file:
            _copy_report_file_to_revision(
                source=source,
                target=revision,
            )

        try:
            revision.save()
        except (
            IntegrityError,
            ValidationError,
        ) as exc:
            raise ReportRevisionError(
                (
                    "The report revision could not be created. "
                    "Refresh the page and try again."
                )
            ) from exc

        revision.included_evidence.set(
            source.included_evidence.all()
        )

        revision.included_analyses.set(
            source.included_analyses.all()
        )

        create_report_audit_log(
            source,
            ReportAuditLog.EventType.REVISION_CREATED,
            (
                "A new draft revision was created "
                "from this report."
            ),
            actor=actor,
            from_status=source.status,
            to_status=source.status,
            metadata={
                "new_report_id": str(
                    revision.pk
                ),
                "new_report_number": (
                    revision.report_number
                ),
                "new_version": (
                    revision.version
                ),
                "revision_reason": truncate_text(
                    reason,
                    2_000,
                ),
            },
        )

        create_report_audit_log(
            revision,
            ReportAuditLog.EventType.CREATED,
            (
                "Draft report revision created from "
                f"{source.report_number}."
            ),
            actor=actor,
            to_status=revision.status,
            metadata={
                "source_report_id": str(
                    source.pk
                ),
                "source_report_number": (
                    source.report_number
                ),
                "source_version": (
                    source.version
                ),
                "revision_reason": truncate_text(
                    reason,
                    2_000,
                ),
                "report_file_copied": bool(
                    copy_report_file
                    and source.report_file
                ),
            },
        )

        return revision


# ============================================================================
# Report File Integrity
# ============================================================================

def calculate_report_file_sha256(
    file_object: Any,
) -> str:
    """
    Calculate SHA-256 from an opened report file.
    """

    sha256 = hashlib.sha256()

    while True:
        chunk = file_object.read(
            1024 * 1024
        )

        if not chunk:
            break

        sha256.update(
            chunk
        )

    return sha256.hexdigest()


def verify_report_file_integrity(
    report: Report,
) -> ReportIntegrityResult:
    """
    Verify the currently stored report file against Report.file_sha256.

    This function does not mutate workflow state. The caller may display the
    result and optionally record a separate audit event.
    """

    if not report.report_file:
        return ReportIntegrityResult(
            checked=False,
            matched=False,
            error=(
                "No report file is attached."
            ),
        )

    stored_hash = normalize_text(
        report.file_sha256
    ).lower()

    if not stored_hash:
        return ReportIntegrityResult(
            checked=False,
            matched=False,
            file_name=(
                report.original_filename
                or report.report_file.name
            ),
            error=(
                "Stored report-file SHA-256 is unavailable."
            ),
        )

    try:
        report.report_file.open(
            "rb"
        )

        calculated_hash = (
            calculate_report_file_sha256(
                report.report_file
            )
        )

    except (
        FileNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        return ReportIntegrityResult(
            checked=False,
            matched=False,
            stored_hash=stored_hash,
            file_name=(
                report.original_filename
                or report.report_file.name
            ),
            error=(
                "The report file could not be read."
            ),
        )

    finally:
        try:
            report.report_file.close()
        except Exception:
            pass

    return ReportIntegrityResult(
        checked=True,
        matched=(
            calculated_hash
            == stored_hash
        ),
        stored_hash=stored_hash,
        calculated_hash=(
            calculated_hash
        ),
        file_name=(
            report.original_filename
            or report.report_file.name
        ),
    )


# ============================================================================
# Download / File Audit
# ============================================================================

def record_report_download(
    report: Report,
    *,
    actor: Any,
) -> ReportAuditLog:
    """
    Record that an authorized user downloaded a report file.
    """

    if not can_download_report(
        actor,
        report,
    ):
        raise ReportAccessError(
            "You cannot download this report."
        )

    return create_report_audit_log(
        report,
        ReportAuditLog.EventType.DOWNLOADED,
        "Investigation report file downloaded.",
        actor=actor,
        from_status=report.status,
        to_status=report.status,
        metadata={
            "file_name": (
                report.original_filename
                or Path(
                    report.report_file.name
                ).name
            ),
            "file_size": (
                report.file_size
            ),
            "file_sha256": (
                report.file_sha256
            ),
        },
    )