"""
AI Engine URL Configuration
"""

from django.urls import path

from . import views


app_name = "ai_engine"


urlpatterns = [
    path(
        "",
        views.ai_dashboard,
        name="dashboard",
    ),

    path(
        "analysis/",
        views.analysis_list,
        name="analysis_list",
    ),

    path(
        "create/",
        views.analysis_create,
        name="analysis_create",
    ),

    path(
        "<uuid:analysis_id>/",
        views.analysis_detail,
        name="analysis_detail",
    ),

    path(
        "<uuid:analysis_id>/run/",
        views.analysis_run,
        name="analysis_run",
    ),

    path(
        "<uuid:analysis_id>/retry/",
        views.analysis_retry,
        name="analysis_retry",
    ),

    path(
        "<uuid:analysis_id>/review/",
        views.analysis_review,
        name="analysis_review",
    ),

    path(
        "<uuid:analysis_id>/archive/",
        views.analysis_archive,
        name="analysis_archive",
    ),

    path(
        "<uuid:analysis_id>/restore/",
        views.analysis_restore,
        name="analysis_restore",
    ),

    path(
        "<uuid:analysis_id>/cancel/",
        views.analysis_cancel,
        name="analysis_cancel",
    ),
]