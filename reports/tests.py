"""
AIDEX Reports regression tests.

These tests protect the report workflow, human-reviewed AI inclusion rules,
SQLite-safe lifecycle transitions, audit logging, revisioning and publication
requirements.
"""

from __future__ import annotations

import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from ai_engine.models import AIAnalysis
from cases.models import Case
from evidence.models import Evidence

from . import views as report_views
from .forms import ReportForm
from .models import Report, ReportAuditLog
from .services import (
    ReportAccessError,
    ReportStateError,
    approve_report,
    archive_report,
    atomic_report_workflow_update,
    create_report_revision,
    publish_report,
    record_report_review,
    reject_report,
    restore_report,
    submit_report_for_review,
)


User = get_user_model()


class ReportsWorkflowRegressionTests(TestCase):
    """
    Regression coverage for report selection, workflow and audit safety.
    """

    def setUp(self) -> None:
        self.temp_media_root = tempfile.mkdtemp(
            prefix="aidex_reports_tests_"
        )

        self.settings_override = override_settings(
            MEDIA_ROOT=self.temp_media_root,
        )
        self.settings_override.enable()

        self.investigator = User.objects.create_user(
            username="reportinvestigator",
            email="reportinvestigator@example.com",
            password="StrongTestPassword123!",
            full_name="Report Investigator",
            badge_id="RPT-INV-001",
            role=User.Role.INVESTIGATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.cyber_officer = User.objects.create_user(
            username="reportofficer",
            email="reportofficer@example.com",
            password="StrongTestPassword123!",
            full_name="Report Cyber Officer",
            badge_id="RPT-CYB-001",
            role=User.Role.CYBER_OFFICER,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.administrator = User.objects.create_user(
            username="reportadmin",
            email="reportadmin@example.com",
            password="StrongTestPassword123!",
            full_name="Report Administrator",
            badge_id="RPT-ADM-001",
            role=User.Role.ADMINISTRATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.case = Case.objects.create(
            case_title="Reports Regression Investigation",
            description=(
                "Regression case used to verify the AIDEX investigation "
                "report workflow and access rules."
            ),
            crime_category=Case.CrimeCategory.PHISHING,
            priority=Case.Priority.HIGH,
            status=Case.Status.UNDER_INVESTIGATION,
            created_by=self.investigator,
            assigned_investigator=self.investigator,
        )

        self.evidence = Evidence.objects.create(
            case=self.case,
            evidence_title="Reports Regression Evidence",
            description=(
                "Digital evidence used by automated reports regression tests."
            ),
            evidence_type=Evidence.EvidenceType.DOCUMENT,
            evidence_file=SimpleUploadedFile(
                "report-evidence.txt",
                b"Evidence content for AIDEX reports regression testing.",
                content_type="text/plain",
            ),
            uploaded_by=self.investigator,
        )

    def tearDown(self) -> None:
        self.settings_override.disable()

        shutil.rmtree(
            self.temp_media_root,
            ignore_errors=True,
        )

    def create_analysis(
        self,
        *,
        title: str,
        reviewed: bool,
    ) -> AIAnalysis:
        reviewed_at = (
            timezone.now()
            if reviewed
            else None
        )

        return AIAnalysis.objects.create(
            evidence=self.evidence,
            title=title,
            analysis_type=AIAnalysis.AnalysisType.GENERAL,
            status=AIAnalysis.Status.COMPLETED,
            priority=AIAnalysis.Priority.MEDIUM,
            provider=AIAnalysis.Provider.GEMINI,
            model_name="gemini-flash-latest",
            prompt_version="v1",
            request_prompt=(
                "Perform a forensic analysis for report regression testing."
            ),
            created_by=self.investigator,
            ai_summary=(
                "Completed AI findings for report regression testing."
            ),
            reviewed_by=(
                self.cyber_officer
                if reviewed
                else None
            ),
            reviewed_at=reviewed_at,
            review_notes=(
                "Human review confirms the AI findings require investigator "
                "verification before evidentiary use."
                if reviewed
                else ""
            ),
        )

    def create_report(
        self,
        *,
        title: str = "Regression Investigation Report",
        with_pdf: bool = False,
    ) -> Report:
        report_file = None

        if with_pdf:
            report_file = SimpleUploadedFile(
                "regression-report.pdf",
                (
                    b"%PDF-1.4\n"
                    b"1 0 obj<</Type/Catalog>>endobj\n"
                    b"%%EOF\n"
                ),
                content_type="application/pdf",
            )

        return Report.objects.create(
            case=self.case,
            report_title=title,
            report_type=Report.ReportType.INVESTIGATION,
            summary=(
                "This report summarizes the investigated cyber incident."
            ),
            findings=(
                "The investigation identified material indicators supported "
                "by the collected digital evidence."
            ),
            evidence_summary=(
                "The report references preserved digital evidence from the "
                "selected investigation case."
            ),
            ai_analysis_summary=(
                "Only human-reviewed AI findings are considered."
            ),
            conclusion=(
                "The available evidence supports continued investigation "
                "and documented follow-up actions."
            ),
            recommendations=(
                "Preserve the evidence, verify findings and maintain the "
                "audit trail."
            ),
            report_file=report_file,
            generated_by=self.investigator,
            status=Report.Status.DRAFT,
            is_confidential=True,
            is_active=True,
        )

    # ------------------------------------------------------------------
    # Human-reviewed AI inclusion rule
    # ------------------------------------------------------------------

    def test_report_form_selector_excludes_unreviewed_ai_analysis(
        self,
    ) -> None:
        reviewed = self.create_analysis(
            title="Reviewed AI Analysis",
            reviewed=True,
        )
        unreviewed = self.create_analysis(
            title="Unreviewed AI Analysis",
            reviewed=False,
        )

        form = ReportForm(
            current_user=self.investigator,
            initial={
                "case": self.case,
            },
        )

        queryset = form.fields[
            "included_analyses"
        ].queryset

        self.assertTrue(
            queryset.filter(
                pk=reviewed.pk
            ).exists()
        )
        self.assertFalse(
            queryset.filter(
                pk=unreviewed.pk
            ).exists()
        )

    def test_report_form_rejects_tampered_unreviewed_ai_analysis(
        self,
    ) -> None:
        unreviewed = self.create_analysis(
            title="Tampered Unreviewed Analysis",
            reviewed=False,
        )

        form = ReportForm(
            data={
                "case": str(self.case.pk),
                "report_title": "Tampered AI Selection Report",
                "report_type": Report.ReportType.INVESTIGATION,
                "summary": "Summary for the report.",
                "findings": "Evidence-grounded findings for the report.",
                "evidence_summary": "Evidence summary for the report.",
                "ai_analysis_summary": "AI analysis summary for the report.",
                "conclusion": "Conclusion for the report.",
                "recommendations": "Recommendations for the report.",
                "included_evidence": [
                    str(self.evidence.pk),
                ],
                "included_analyses": [
                    str(unreviewed.pk),
                ],
                "is_confidential": "on",
            },
            current_user=self.investigator,
        )

        self.assertFalse(
            form.is_valid()
        )
        self.assertIn(
            "included_analyses",
            form.errors,
        )

    # ------------------------------------------------------------------
    # File validation and download privacy
    # ------------------------------------------------------------------

    def test_report_form_rejects_executable_renamed_as_pdf(
        self,
    ) -> None:
        form = ReportForm(
            data={
                "case": str(self.case.pk),
                "report_title": "Renamed Executable Report",
                "report_type": Report.ReportType.INVESTIGATION,
                "summary": "Summary for the report upload validation.",
                "findings": "Evidence-grounded report upload findings.",
                "evidence_summary": "Evidence summary for validation.",
                "ai_analysis_summary": "Reviewed AI summary for validation.",
                "conclusion": "Conclusion for report upload validation.",
                "recommendations": "Recommendations for upload validation.",
                "is_confidential": "on",
            },
            files={
                "report_file": SimpleUploadedFile(
                    "renamed-executable.pdf",
                    b"MZ" + (b"X" * 128),
                    content_type="application/pdf",
                ),
            },
            current_user=self.investigator,
        )

        self.assertFalse(
            form.is_valid()
        )
        self.assertIn(
            "report_file",
            form.errors,
        )
        self.assertIn(
            "Executable files are not allowed",
            form.errors["report_file"][0],
        )

    def test_report_model_rejects_executable_renamed_as_pdf(
        self,
    ) -> None:
        report = self.create_report(
            title="Model Signature Validation Report",
        )
        report.report_file = SimpleUploadedFile(
            "renamed-executable.pdf",
            b"MZ" + (b"X" * 128),
            content_type="application/pdf",
        )

        with self.assertRaises(
            ValidationError
        ):
            report.save()

    def test_report_download_disables_private_file_caching(
        self,
    ) -> None:
        report = self.create_report(
            title="Private Download Header Report",
            with_pdf=True,
        )
        self.client.force_login(
            self.investigator
        )

        response = self.client.get(
            reverse(
                "reports:report_download",
                kwargs={
                    "report_id": report.pk,
                },
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertEqual(
            response["Cache-Control"],
            "private, no-store, max-age=0",
        )
        self.assertEqual(
            response["Pragma"],
            "no-cache",
        )
        self.assertEqual(
            response["X-Content-Type-Options"],
            "nosniff",
        )
        self.assertIn(
            "attachment;",
            response["Content-Disposition"],
        )

        response.close()

    # ------------------------------------------------------------------
    # Main lifecycle
    # ------------------------------------------------------------------

    def test_submit_review_approve_publish_workflow_and_audit(
        self,
    ) -> None:
        report = self.create_report(
            with_pdf=True,
        )

        report = submit_report_for_review(
            report,
            actor=self.investigator,
            submission_note=(
                "The draft is ready for independent formal review."
            ),
        )

        self.assertEqual(
            report.status,
            Report.Status.UNDER_REVIEW,
        )

        report = record_report_review(
            report,
            actor=self.cyber_officer,
            review_notes=(
                "The evidence references and conclusions were reviewed and "
                "are suitable for administrator approval."
            ),
        )

        self.assertEqual(
            report.reviewed_by,
            self.cyber_officer,
        )
        self.assertIsNotNone(
            report.reviewed_date
        )

        report = approve_report(
            report,
            actor=self.administrator,
            approval_notes=(
                "Approved after independent review and evidence verification."
            ),
        )

        self.assertEqual(
            report.status,
            Report.Status.APPROVED,
        )
        self.assertEqual(
            report.approved_by,
            self.administrator,
        )

        report = publish_report(
            report,
            actor=self.administrator,
            publication_note=(
                "Published as the approved investigation report."
            ),
        )

        self.assertEqual(
            report.status,
            Report.Status.PUBLISHED,
        )
        self.assertEqual(
            report.published_by,
            self.administrator,
        )
        self.assertIsNotNone(
            report.published_date
        )

        event_types = list(
            ReportAuditLog.objects
            .filter(
                report=report
            )
            .values_list(
                "event_type",
                flat=True,
            )
        )

        self.assertIn(
            ReportAuditLog.EventType.SUBMITTED,
            event_types,
        )
        self.assertIn(
            ReportAuditLog.EventType.REVIEWED,
            event_types,
        )
        self.assertIn(
            ReportAuditLog.EventType.APPROVED,
            event_types,
        )
        self.assertIn(
            ReportAuditLog.EventType.PUBLISHED,
            event_types,
        )

    def test_author_cannot_formally_review_own_report(
        self,
    ) -> None:
        report = self.create_report()

        report = submit_report_for_review(
            report,
            actor=self.investigator,
        )

        with self.assertRaises(
            ReportAccessError
        ):
            record_report_review(
                report,
                actor=self.investigator,
                review_notes=(
                    "The author must not be able to formally review this."
                ),
            )

    def test_reject_report_records_reason_and_reviewer(
        self,
    ) -> None:
        report = self.create_report(
            title="Regression Rejection Report",
        )

        report = submit_report_for_review(
            report,
            actor=self.investigator,
        )

        report = reject_report(
            report,
            actor=self.cyber_officer,
            rejection_reason=(
                "The evidence narrative requires additional clarification "
                "before approval."
            ),
        )

        self.assertEqual(
            report.status,
            Report.Status.REJECTED,
        )
        self.assertEqual(
            report.reviewed_by,
            self.cyber_officer,
        )
        self.assertIn(
            "clarification",
            report.rejection_reason.lower(),
        )
        self.assertTrue(
            ReportAuditLog.objects.filter(
                report=report,
                event_type=ReportAuditLog.EventType.REJECTED,
            ).exists()
        )

    def test_publish_requires_pdf_report_file(
        self,
    ) -> None:
        report = self.create_report(
            title="Non PDF Publication Report",
        )

        report.report_file = SimpleUploadedFile(
            "non-pdf-report.doc",
            (
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
                b"Legacy DOC payload for publication validation."
            ),
            content_type="application/msword",
        )
        report.save()

        report = submit_report_for_review(
            report,
            actor=self.investigator,
        )

        report = record_report_review(
            report,
            actor=self.cyber_officer,
            review_notes=(
                "The report content was reviewed for publication testing."
            ),
        )

        report = approve_report(
            report,
            actor=self.administrator,
        )

        with self.assertRaises(
            ReportStateError
        ):
            publish_report(
                report,
                actor=self.administrator,
            )

    # ------------------------------------------------------------------
    # Archive / restore
    # ------------------------------------------------------------------

    def test_archive_and_restore_preserve_previous_status(
        self,
    ) -> None:
        report = self.create_report(
            title="Archive Restore Regression Report",
        )

        report = archive_report(
            report,
            actor=self.cyber_officer,
            reason=(
                "Archiving this report after regression workflow testing."
            ),
        )

        self.assertEqual(
            report.status,
            Report.Status.ARCHIVED,
        )
        self.assertFalse(
            report.is_active
        )
        self.assertEqual(
            report.pre_archive_status,
            Report.Status.DRAFT,
        )

        report = restore_report(
            report,
            actor=self.administrator,
        )

        self.assertEqual(
            report.status,
            Report.Status.DRAFT,
        )
        self.assertTrue(
            report.is_active
        )
        self.assertTrue(
            ReportAuditLog.objects.filter(
                report=report,
                event_type=ReportAuditLog.EventType.RESTORED,
            ).exists()
        )

    def test_repeated_archive_does_not_create_duplicate_audit_event(
        self,
    ) -> None:
        report = self.create_report(
            title="Single Archive Audit Report",
        )

        first = archive_report(
            report,
            actor=self.cyber_officer,
            reason=(
                "Archiving the report once for duplicate audit protection."
            ),
        )

        second = archive_report(
            first,
            actor=self.cyber_officer,
            reason=(
                "This second archive request must not create another event."
            ),
        )

        self.assertEqual(
            second.status,
            Report.Status.ARCHIVED,
        )
        self.assertEqual(
            ReportAuditLog.objects.filter(
                report=report,
                event_type=ReportAuditLog.EventType.ARCHIVED,
            ).count(),
            1,
        )

    # ------------------------------------------------------------------
    # SQLite-safe optimistic concurrency
    # ------------------------------------------------------------------

    def test_stale_report_snapshot_is_rejected_by_atomic_update(
        self,
    ) -> None:
        report = self.create_report(
            title="Stale Snapshot Regression Report",
        )

        stale_updated_date = report.updated_date

        newer_update_time = timezone.now()

        Report.objects.filter(
            pk=report.pk,
        ).update(
            report_title=(
                "Newer Concurrent Report Title"
            ),
            updated_date=newer_update_time,
        )

        with self.assertRaises(
            ReportStateError
        ):
            atomic_report_workflow_update(
                report,
                expected_status=Report.Status.DRAFT,
                expected_updated_date=stale_updated_date,
                expected_is_active=True,
                updates={
                    "status": Report.Status.UNDER_REVIEW,
                },
                action_label="Concurrency Regression",
            )

        report.refresh_from_db()

        self.assertEqual(
            report.status,
            Report.Status.DRAFT,
        )
        self.assertEqual(
            report.report_title,
            "Newer Concurrent Report Title",
        )

    # ------------------------------------------------------------------
    # Revisioning
    # ------------------------------------------------------------------

    def test_revision_increments_version_and_copies_references(
        self,
    ) -> None:
        reviewed_analysis = self.create_analysis(
            title="Revision Reviewed Analysis",
            reviewed=True,
        )

        report = self.create_report(
            title="Revision Regression Report",
        )

        report.included_evidence.add(
            self.evidence
        )
        report.included_analyses.add(
            reviewed_analysis
        )

        revision = create_report_revision(
            report,
            actor=self.investigator,
            revision_reason=(
                "Create a new draft version after receiving review feedback."
            ),
        )

        self.assertEqual(
            revision.version,
            report.version + 1,
        )
        self.assertEqual(
            revision.supersedes,
            report,
        )
        self.assertEqual(
            revision.status,
            Report.Status.DRAFT,
        )
        self.assertTrue(
            revision.included_evidence.filter(
                pk=self.evidence.pk
            ).exists()
        )
        self.assertTrue(
            revision.included_analyses.filter(
                pk=reviewed_analysis.pk
            ).exists()
        )
        self.assertTrue(
            ReportAuditLog.objects.filter(
                report=report,
                event_type=(
                    ReportAuditLog.EventType.REVISION_CREATED
                ),
            ).exists()
        )

    def test_report_edit_version_detects_stale_record(
        self,
    ) -> None:
        """
        Protect report-edit optimistic locking so an older browser tab cannot
        silently overwrite newer report content.
        """

        report = self.create_report(
            title="Stale Edit Protection Report",
        )

        token = report_views.build_report_edit_version(
            report
        )

        self.assertTrue(
            report_views.report_edit_version_matches(
                report,
                token,
            )
        )

        Report.objects.filter(
            pk=report.pk
        ).update(
            report_title="Newer Concurrent Report Title",
            updated_date=timezone.now(),
        )

        report.refresh_from_db()

        self.assertFalse(
            report_views.report_edit_version_matches(
                report,
                token,
            )
        )
