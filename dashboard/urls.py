"""
AIDEX Dashboard URL Configuration
================================

This module defines all URL routes for the Dashboard application.

Author:
    Harsh

Project:
    AIDEX - AI Digital Evidence Intelligence & Investigation System

Available Dashboards:
    • Dashboard Redirect
    • Administrator Dashboard
    • Investigator Dashboard
    • Cyber Officer Dashboard
"""

from django.urls import path

from .views import (
    admin_dashboard,
    cyber_officer_dashboard,
    dashboard_redirect,
    investigator_dashboard,
)

app_name = "dashboard"

urlpatterns = [

    # ==========================================================
    # Dashboard Redirect
    # ==========================================================

    path(
        "",
        dashboard_redirect,
        name="dashboard_redirect",
    ),

    # ==========================================================
    # Administrator Dashboard
    # ==========================================================

    path(
        "admin/",
        admin_dashboard,
        name="admin_dashboard",
    ),

    # ==========================================================
    # Investigator Dashboard
    # ==========================================================

    path(
        "investigator/",
        investigator_dashboard,
        name="investigator_dashboard",
    ),

    # ==========================================================
    # Cyber Officer Dashboard
    # ==========================================================

    path(
        "cyber-officer/",
        cyber_officer_dashboard,
        name="cyber_officer_dashboard",
    ),
]