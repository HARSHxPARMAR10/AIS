"""Authenticated access to user-uploaded AIDEX media.

Uploaded evidence, report files and profile photos must never be exposed by a
public ``/media/`` directory.  This view resolves a stored FileField name only
after checking the logged-in user's object-level access.
"""

from __future__ import annotations

import mimetypes
import posixpath

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404, HttpRequest, HttpResponse
from django.views.decorators.http import require_GET

from evidence.views import get_accessible_evidence
from reports.services import get_accessible_reports


User = get_user_model()


def _normalize_media_name(file_path: str) -> str:
    """Return a safe storage-relative name or raise a 404."""

    normalized = posixpath.normpath(
        str(file_path or "").replace("\\", "/")
    ).lstrip("/")

    if (
        not normalized
        or normalized == "."
        or normalized.startswith("../")
        or "/../" in f"/{normalized}/"
    ):
        raise Http404("Media file not found.")

    return normalized


def _private_file_response(
    field_file,
    *,
    filename: str,
) -> FileResponse:
    content_type = (
        mimetypes.guess_type(filename)[0]
        or "application/octet-stream"
    )

    try:
        file_handle = field_file.open("rb")
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise Http404("Media file not found.") from exc

    response = FileResponse(
        file_handle,
        as_attachment=False,
        filename=filename,
        content_type=content_type,
    )
    response["Cache-Control"] = "private, no-store, max-age=0"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@login_required
@require_GET
def protected_media(
    request: HttpRequest,
    file_path: str,
) -> HttpResponse:
    """Serve only media that the current user is authorized to view."""

    storage_name = _normalize_media_name(file_path)

    evidence = (
        get_accessible_evidence(request.user)
        .filter(evidence_file=storage_name)
        .first()
    )
    if evidence is not None:
        return _private_file_response(
            evidence.evidence_file,
            filename=(
                evidence.original_filename
                or evidence.evidence_file.name.rsplit("/", 1)[-1]
            ),
        )

    report = (
        get_accessible_reports(
            request.user,
            include_archived=True,
        )
        .filter(report_file=storage_name)
        .first()
    )
    if report is not None and report.report_file:
        return _private_file_response(
            report.report_file,
            filename=(
                report.original_filename
                or report.report_file.name.rsplit("/", 1)[-1]
            ),
        )

    profile_owner = User.objects.filter(
        profile_photo=storage_name,
        pk=request.user.pk,
    ).first()
    if profile_owner is not None and profile_owner.profile_photo:
        return _private_file_response(
            profile_owner.profile_photo,
            filename=profile_owner.profile_photo.name.rsplit("/", 1)[-1],
        )

    raise Http404("Media file not found.")