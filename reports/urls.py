"""
AIDEX Reports URL Configuration

Professional routing for the investigation-report module.
"""

from django.urls import path

from . import views


app_name = "reports"


urlpatterns = [
    # ---------------------------------------------------------------------
    # Dashboard / register
    # ---------------------------------------------------------------------
    path(
        "",
        views.report_dashboard,
        name="dashboard",
    ),
    path(
        "home/",
        views.report_dashboard,
        name="report_home",
    ),
    path(
        "list/",
        views.report_list,
        name="report_list",
    ),

    # ---------------------------------------------------------------------
    # Create
    # ---------------------------------------------------------------------
    path(
        "create/",
        views.report_create,
        name="report_create",
    ),

    # ---------------------------------------------------------------------
    # Report detail / editing
    # ---------------------------------------------------------------------
    path(
        "<uuid:report_id>/",
        views.report_detail,
        name="report_detail",
    ),
    path(
        "<uuid:report_id>/edit/",
        views.report_update,
        name="report_update",
    ),

    # ---------------------------------------------------------------------
    # Review workflow
    # ---------------------------------------------------------------------
    path(
        "<uuid:report_id>/submit-review/",
        views.report_submit_review,
        name="report_submit_review",
    ),
    path(
        "<uuid:report_id>/review/",
        views.report_review,
        name="report_review",
    ),
    path(
        "<uuid:report_id>/approve/",
        views.report_approve,
        name="report_approve",
    ),
    path(
        "<uuid:report_id>/reject/",
        views.report_reject,
        name="report_reject",
    ),
    path(
        "<uuid:report_id>/publish/",
        views.report_publish,
        name="report_publish",
    ),

    # ---------------------------------------------------------------------
    # Archive / restore
    # ---------------------------------------------------------------------
    path(
        "<uuid:report_id>/archive/",
        views.report_archive,
        name="report_archive",
    ),
    path(
        "<uuid:report_id>/restore/",
        views.report_restore,
        name="report_restore",
    ),

    # ---------------------------------------------------------------------
    # Revision / history
    # ---------------------------------------------------------------------
    path(
        "<uuid:report_id>/revision/",
        views.report_revision_create,
        name="report_revision_create",
    ),
    path(
        "<uuid:report_id>/audit/",
        views.report_audit,
        name="report_audit",
    ),

    # ---------------------------------------------------------------------
    # File integrity / download / print
    # ---------------------------------------------------------------------
    path(
        "<uuid:report_id>/integrity-check/",
        views.report_integrity_check,
        name="report_integrity_check",
    ),
    path(
        "<uuid:report_id>/download/",
        views.report_download,
        name="report_download",
    ),
    path(
        "<uuid:report_id>/print/",
        views.report_print,
        name="report_print",
    ),
]