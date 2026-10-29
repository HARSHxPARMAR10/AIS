from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from dashboard.views import landing_page
from .media_views import protected_media


urlpatterns = [
    # Public Landing Page
    path(
        "",
        landing_page,
        name="landing",
    ),

    # Django Admin
    path(
        "admin/",
        admin.site.urls,
    ),

    # Accounts
    path(
        "accounts/",
        include("accounts.urls"),
    ),

    # Dashboard
    path(
        "dashboard/",
        include("dashboard.urls"),
    ),

    # Cases
    path(
        "cases/",
        include("cases.urls"),
    ),

    # Evidence
    path(
        "evidence/",
        include("evidence.urls"),
    ),

    # Reports
    path(
        "reports/",
        include("reports.urls"),
    ),

    # AI Engine
    path(
        "ai/",
        include("ai_engine.urls"),
    ),

    # Authenticated, role-aware media preview endpoint.
    path(
        "protected-media/<path:file_path>",
        protected_media,
        name="protected_media",
    ),
]


if settings.DEBUG:
    urlpatterns += static(
        settings.STATIC_URL,
        document_root=settings.STATIC_ROOT,
    )