"""
AIDEX Cases URL Configuration

Defines routes for the complete Case Management module.
"""

from django.urls import path

from . import views


app_name = "cases"


urlpatterns = [
    path(
        "",
        views.case_home,
        name="case_home",
    ),

    path(
        "list/",
        views.case_list,
        name="case_list",
    ),

    path(
        "create/",
        views.case_create,
        name="case_create",
    ),

    path(
        "<uuid:case_id>/",
        views.case_detail,
        name="case_detail",
    ),

    path(
        "<uuid:case_id>/update/",
        views.case_update,
        name="case_update",
    ),

    path(
        "<uuid:case_id>/assign/",
        views.case_assign,
        name="case_assign",
    ),

    path(
        "<uuid:case_id>/status/",
        views.case_status_update,
        name="case_status_update",
    ),

    path(
        "<uuid:case_id>/archive/",
        views.case_archive,
        name="case_archive",
    ),

    path(
        "<uuid:case_id>/restore/",
        views.case_restore,
        name="case_restore",
    ),
]