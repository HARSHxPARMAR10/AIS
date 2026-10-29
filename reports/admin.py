"""
AIDEX Reports Admin

Administrative oversight for investigation reports.

Important design choice:
Report workflow mutations are intentionally NOT performed from Django Admin.
The public/internal AIDEX report workflow uses reports.services so that
status transitions, locking and audit logging remain consistent.

Django Admin is therefore used as a read-only oversight console for:
- report metadata
- report lifecycle state
- linked evidence / AI analyses
- integrity fingerprints
- immutable audit events
"""

from __future__ import annotations

from django.contrib import admin
from django.utils.html import format_html

from .models import Report, ReportAuditLog


# ============================================================================
# Report Admin
# ============================================================================

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    """
    Read-only governance view for investigation reports.

    Report creation/editing/review/approval/publication should be performed
    through the AIDEX application workflow, not through Django Admin.
    """

    list_display = (
        "report_number",
        "report_title",
        "case_number_display",
        "report_type_display",
        "version",
        "status_badge",
        "generated_by",
        "reviewed_by",
        "approved_by",
        "confidential_badge",
        "active_badge",
        "generated_date",
    )

    list_filter = (
        "status",
        "report_type",
        "is_confidential",
        "is_active",
        "generated_date",
        "reviewed_date",
        "approved_date",
        "published_date",
    )

    search_fields = (
        "report_number",
        "report_title",
        "case__case_number",
        "case__case_title",
        "generated_by__username",
        "generated_by__email",
        "reviewed_by__username",
        "approved_by__username",
        "file_sha256",
    )

    ordering = (
        "-generated_date",
    )

    date_hierarchy = "generated_date"

    list_select_related = (
        "case",
        "generated_by",
        "reviewed_by",
        "approved_by",
        "published_by",
        "archived_by",
        "supersedes",
    )

    filter_horizontal = (
        "included_evidence",
        "included_analyses",
    )

    readonly_fields = (
        "id",
        "report_number",
        "case",
        "report_title",
        "report_type",
        "version",
        "supersedes",
        "summary",
        "findings",
        "evidence_summary",
        "ai_analysis_summary",
        "conclusion",
        "recommendations",
        "review_notes",
        "approval_notes",
        "rejection_reason",
        "report_file",
        "original_filename",
        "file_size",
        "file_size_display",
        "file_sha256",
        "generated_by",
        "reviewed_by",
        "approved_by",
        "published_by",
        "archived_by",
        "status",
        "pre_archive_status",
        "generated_date",
        "reviewed_date",
        "approved_date",
        "published_date",
        "archived_at",
        "updated_date",
        "archive_reason",
        "is_confidential",
        "is_active",
        "included_evidence_display",
        "included_analyses_display",
        "audit_event_count",
    )

    fieldsets = (
        (
            "Report Identity",
            {
                "fields": (
                    "id",
                    "report_number",
                    "case",
                    "report_title",
                    "report_type",
                    "version",
                    "supersedes",
                )
            },
        ),
        (
            "Investigation Narrative",
            {
                "fields": (
                    "summary",
                    "findings",
                    "evidence_summary",
                    "ai_analysis_summary",
                    "conclusion",
                    "recommendations",
                ),
                "classes": (
                    "collapse",
                ),
            },
        ),
        (
            "Evidence & AI References",
            {
                "fields": (
                    "included_evidence_display",
                    "included_analyses_display",
                )
            },
        ),
        (
            "Report File Integrity",
            {
                "fields": (
                    "report_file",
                    "original_filename",
                    "file_size",
                    "file_size_display",
                    "file_sha256",
                )
            },
        ),
        (
            "Review & Approval",
            {
                "fields": (
                    "status",
                    "reviewed_by",
                    "reviewed_date",
                    "review_notes",
                    "approved_by",
                    "approved_date",
                    "approval_notes",
                    "rejection_reason",
                )
            },
        ),
        (
            "Publication",
            {
                "fields": (
                    "published_by",
                    "published_date",
                )
            },
        ),
        (
            "Archive / Restore History",
            {
                "fields": (
                    "pre_archive_status",
                    "archive_reason",
                    "archived_by",
                    "archived_at",
                    "is_active",
                )
            },
        ),
        (
            "Ownership / Record Metadata",
            {
                "fields": (
                    "generated_by",
                    "generated_date",
                    "updated_date",
                    "is_confidential",
                    "audit_event_count",
                )
            },
        ),
    )

    # ---------------------------------------------------------------------
    # Admin access behavior
    # ---------------------------------------------------------------------

    def has_add_permission(
        self,
        request,
    ):
        """
        Reports must be created through AIDEX workflow views.
        """
        return False

    def has_change_permission(
        self,
        request,
        obj=None,
    ):
        """
        Permit opening the change-form page for read-only inspection.

        Because every model field is read-only and save buttons are removed
        below, this remains an oversight interface rather than a workflow
        bypass.
        """
        return bool(
            request.user.is_active
            and request.user.is_superuser
        )

    def has_delete_permission(
        self,
        request,
        obj=None,
    ):
        """
        Investigation reports should be archived, not deleted.
        """
        return False

    def has_view_permission(
        self,
        request,
        obj=None,
    ):
        return bool(
            request.user.is_active
            and request.user.is_superuser
        )

    def get_actions(
        self,
        request,
    ):
        """
        Disable bulk actions so lifecycle state cannot be bypassed.
        """
        return {}

    def get_readonly_fields(
        self,
        request,
        obj=None,
    ):
        return self.readonly_fields

    def render_change_form(
        self,
        request,
        context,
        add=False,
        change=False,
        form_url="",
        obj=None,
    ):
        """
        Remove mutation controls from the read-only oversight page.
        """
        context.update(
            {
                "show_save": False,
                "show_save_and_continue": False,
                "show_save_and_add_another": False,
                "show_delete": False,
            }
        )

        return super().render_change_form(
            request,
            context,
            add=add,
            change=change,
            form_url=form_url,
            obj=obj,
        )

    # ---------------------------------------------------------------------
    # Display helpers
    # ---------------------------------------------------------------------

    @admin.display(
        description="Case",
        ordering="case__case_number",
    )
    def case_number_display(
        self,
        obj: Report,
    ) -> str:
        return obj.case.case_number

    @admin.display(
        description="Type",
        ordering="report_type",
    )
    def report_type_display(
        self,
        obj: Report,
    ) -> str:
        return obj.get_report_type_display()

    @admin.display(
        description="Status",
        ordering="status",
    )
    def status_badge(
        self,
        obj: Report,
    ):
        colors = {
            Report.Status.DRAFT: (
                "#64748b",
                "#f8fafc",
            ),
            Report.Status.UNDER_REVIEW: (
                "#d97706",
                "#fffbeb",
            ),
            Report.Status.APPROVED: (
                "#15803d",
                "#f0fdf4",
            ),
            Report.Status.REJECTED: (
                "#b91c1c",
                "#fef2f2",
            ),
            Report.Status.PUBLISHED: (
                "#0e7490",
                "#ecfeff",
            ),
            Report.Status.ARCHIVED: (
                "#6d28d9",
                "#f5f3ff",
            ),
        }

        foreground, background = colors.get(
            obj.status,
            (
                "#475569",
                "#f8fafc",
            ),
        )

        return format_html(
            (
                '<span style="'
                'display:inline-block;'
                'padding:4px 9px;'
                'border-radius:999px;'
                'font-size:11px;'
                'font-weight:700;'
                'color:{};'
                'background:{};'
                'border:1px solid {}33;'
                '">{}</span>'
            ),
            foreground,
            background,
            foreground,
            obj.get_status_display(),
        )

    @admin.display(
        description="Confidential",
        boolean=False,
        ordering="is_confidential",
    )
    def confidential_badge(
        self,
        obj: Report,
    ):
        if obj.is_confidential:
            return format_html(
                '<strong style="color:#7e22ce;">CONFIDENTIAL</strong>'
            )

        return format_html(
            '<span style="color:#64748b;">Standard</span>'
        )

    @admin.display(
        description="Active",
        boolean=True,
        ordering="is_active",
    )
    def active_badge(
        self,
        obj: Report,
    ) -> bool:
        return obj.is_active

    @admin.display(
        description="File Size",
    )
    def file_size_display(
        self,
        obj: Report,
    ) -> str:
        if not obj.file_size:
            return "—"

        return f"{obj.file_size_mb:.2f} MB"

    @admin.display(
        description="Included Evidence",
    )
    def included_evidence_display(
        self,
        obj: Report,
    ):
        evidence_items = obj.included_evidence.all()

        if not evidence_items:
            return "No evidence linked."

        rows = []

        for evidence in evidence_items[:50]:
            title = (
                getattr(
                    evidence,
                    "evidence_title",
                    "",
                )
                or str(evidence)
            )

            number = (
                getattr(
                    evidence,
                    "evidence_number",
                    "",
                )
                or str(evidence.pk)
            )

            rows.append(
                f"{number} — {title}"
            )

        if evidence_items.count() > 50:
            rows.append(
                (
                    f"... and "
                    f"{evidence_items.count() - 50} more"
                )
            )

        return format_html(
            "<br>".join(
                "{}".format(row)
                for row in rows
            )
        )

    @admin.display(
        description="Included AI Analyses",
    )
    def included_analyses_display(
        self,
        obj: Report,
    ):
        analyses = obj.included_analyses.all()

        if not analyses:
            return "No AI analyses linked."

        rows = []

        for analysis in analyses[:50]:
            title = (
                getattr(
                    analysis,
                    "title",
                    "",
                )
                or str(analysis)
            )

            number = (
                getattr(
                    analysis,
                    "analysis_number",
                    "",
                )
                or str(analysis.pk)
            )

            rows.append(
                f"{number} — {title}"
            )

        if analyses.count() > 50:
            rows.append(
                (
                    f"... and "
                    f"{analyses.count() - 50} more"
                )
            )

        return format_html(
            "<br>".join(
                "{}".format(row)
                for row in rows
            )
        )

    @admin.display(
        description="Audit Events",
    )
    def audit_event_count(
        self,
        obj: Report,
    ) -> int:
        return obj.audit_logs.count()


# ============================================================================
# Report Audit Admin
# ============================================================================

@admin.register(ReportAuditLog)
class ReportAuditLogAdmin(admin.ModelAdmin):
    """
    Immutable administrative audit viewer.
    """

    list_display = (
        "created_at",
        "report_number_display",
        "event_type",
        "actor",
        "from_status",
        "to_status",
        "short_message",
    )

    list_filter = (
        "event_type",
        "created_at",
        "from_status",
        "to_status",
    )

    search_fields = (
        "report__report_number",
        "report__report_title",
        "report__case__case_number",
        "actor__username",
        "actor__email",
        "message",
    )

    ordering = (
        "-created_at",
    )

    date_hierarchy = "created_at"

    list_select_related = (
        "report",
        "report__case",
        "actor",
    )

    readonly_fields = (
        "id",
        "report",
        "event_type",
        "actor",
        "message",
        "from_status",
        "to_status",
        "metadata",
        "created_at",
    )

    fieldsets = (
        (
            "Audit Event",
            {
                "fields": (
                    "id",
                    "report",
                    "event_type",
                    "actor",
                    "created_at",
                )
            },
        ),
        (
            "Workflow Transition",
            {
                "fields": (
                    "from_status",
                    "to_status",
                )
            },
        ),
        (
            "Event Details",
            {
                "fields": (
                    "message",
                    "metadata",
                )
            },
        ),
    )

    def has_add_permission(
        self,
        request,
    ):
        """
        Audit events are generated by application services.
        """
        return False

    def has_change_permission(
        self,
        request,
        obj=None,
    ):
        """
        Allow superusers to inspect an event, never mutate it.
        """
        return bool(
            request.user.is_active
            and request.user.is_superuser
        )

    def has_delete_permission(
        self,
        request,
        obj=None,
    ):
        """
        Report audit events are retained.
        """
        return False

    def has_view_permission(
        self,
        request,
        obj=None,
    ):
        return bool(
            request.user.is_active
            and request.user.is_superuser
        )

    def get_actions(
        self,
        request,
    ):
        return {}

    def render_change_form(
        self,
        request,
        context,
        add=False,
        change=False,
        form_url="",
        obj=None,
    ):
        context.update(
            {
                "show_save": False,
                "show_save_and_continue": False,
                "show_save_and_add_another": False,
                "show_delete": False,
            }
        )

        return super().render_change_form(
            request,
            context,
            add=add,
            change=change,
            form_url=form_url,
            obj=obj,
        )

    @admin.display(
        description="Report",
        ordering="report__report_number",
    )
    def report_number_display(
        self,
        obj: ReportAuditLog,
    ) -> str:
        return obj.report.report_number

    @admin.display(
        description="Message",
    )
    def short_message(
        self,
        obj: ReportAuditLog,
    ) -> str:
        message = (
            obj.message
            or ""
        )

        if len(message) <= 80:
            return message

        return (
            message[:77]
            + "..."
        )