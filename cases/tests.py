"""
AIDEX Cases regression tests.

Coverage:
- UUID-safe CaseForm create/update detection
- investigator case creation and automatic assignment
- role-based case visibility
- assignment permissions and OPEN -> ASSIGNED behavior
- controlled status transitions
- archived-case lifecycle and restore status
- stale edit-version protection
- duplicate active case-title validation
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .forms import CaseForm, CaseStatusForm
from .models import Case
from . import views as case_views


User = get_user_model()


class CasesWorkflowRegressionTests(TestCase):
    """
    Regression coverage for AIDEX case-management workflows.
    """

    def setUp(self) -> None:
        self.investigator = User.objects.create_user(
            username="caseinvestigator",
            email="caseinvestigator@example.com",
            password="StrongTestPassword123!",
            full_name="Case Investigator",
            badge_id="CASE-INV-001",
            role=User.Role.INVESTIGATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.other_investigator = User.objects.create_user(
            username="othercaseinvestigator",
            email="othercaseinvestigator@example.com",
            password="StrongTestPassword123!",
            full_name="Other Case Investigator",
            badge_id="CASE-INV-002",
            role=User.Role.INVESTIGATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.cyber_officer = User.objects.create_user(
            username="casecyberofficer",
            email="casecyberofficer@example.com",
            password="StrongTestPassword123!",
            full_name="Case Cyber Officer",
            badge_id="CASE-CYB-001",
            role=User.Role.CYBER_OFFICER,
            account_status=User.AccountStatus.ACTIVE,
        )

        self.administrator = User.objects.create_user(
            username="caseadministrator",
            email="caseadministrator@example.com",
            password="StrongTestPassword123!",
            full_name="Case Administrator",
            badge_id="CASE-ADM-001",
            role=User.Role.ADMINISTRATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

    def create_case(
        self,
        *,
        title: str = "Regression Cyber Crime Case",
        created_by=None,
        assigned_investigator=None,
        status: str = Case.Status.OPEN,
        priority: str = Case.Priority.HIGH,
    ) -> Case:
        return Case.objects.create(
            case_title=title,
            description=(
                "Detailed cyber-crime investigation description used for "
                "AIDEX case workflow regression testing."
            ),
            crime_category=Case.CrimeCategory.PHISHING,
            priority=priority,
            status=status,
            created_by=created_by or self.investigator,
            assigned_investigator=assigned_investigator,
            is_active=True,
        )

    # ------------------------------------------------------------------
    # Form / creation regression
    # ------------------------------------------------------------------

    def test_case_form_treats_unsaved_uuid_instance_as_create(
        self,
    ) -> None:
        """
        UUID primary keys exist before first save, so CaseForm must use
        ModelState.adding instead of instance.pk to detect create/update.
        """

        form = CaseForm(
            current_user=self.administrator,
        )

        self.assertFalse(
            form.is_update
        )

        self.assertEqual(
            list(form.fields["status"].choices),
            [
                (
                    Case.Status.OPEN,
                    Case.Status.OPEN.label,
                ),
            ],
        )

    def test_investigator_create_auto_assigns_self_and_sets_assigned_status(
        self,
    ) -> None:
        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "cases:case_create"
            ),
            data={
                "case_title": "Investigator Created Phishing Case",
                "description": (
                    "A detailed phishing investigation created directly by "
                    "the assigned investigator for regression testing."
                ),
                "crime_category": Case.CrimeCategory.PHISHING,
                "priority": Case.Priority.HIGH,
                "status": Case.Status.OPEN,
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        created = Case.objects.get(
            case_title="Investigator Created Phishing Case"
        )

        self.assertEqual(
            created.created_by,
            self.investigator,
        )
        self.assertEqual(
            created.assigned_investigator,
            self.investigator,
        )
        self.assertEqual(
            created.status,
            Case.Status.ASSIGNED,
        )
        self.assertTrue(
            created.is_active
        )

    def test_duplicate_active_case_title_is_rejected(
        self,
    ) -> None:
        self.create_case(
            title="Duplicate Active Investigation",
        )

        form = CaseForm(
            data={
                "case_title": " duplicate active investigation ",
                "description": (
                    "Another sufficiently detailed cyber-crime description "
                    "for duplicate-title validation."
                ),
                "crime_category": Case.CrimeCategory.OTHER,
                "priority": Case.Priority.MEDIUM,
                "status": Case.Status.OPEN,
                "assigned_investigator": "",
            },
            current_user=self.administrator,
        )

        self.assertFalse(
            form.is_valid()
        )
        self.assertIn(
            "case_title",
            form.errors,
        )

    # ------------------------------------------------------------------
    # Access / assignment
    # ------------------------------------------------------------------

    def test_investigator_cannot_view_unrelated_case(
        self,
    ) -> None:
        own_case = self.create_case(
            title="Investigator Accessible Case",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.ASSIGNED,
        )

        unrelated_case = self.create_case(
            title="Other Investigator Private Case",
            created_by=self.other_investigator,
            assigned_investigator=self.other_investigator,
            status=Case.Status.ASSIGNED,
        )

        queryset = case_views.get_accessible_cases(
            self.investigator
        )

        self.assertTrue(
            queryset.filter(
                pk=own_case.pk
            ).exists()
        )
        self.assertFalse(
            queryset.filter(
                pk=unrelated_case.pk
            ).exists()
        )

    def test_administrator_assignment_moves_open_case_to_assigned(
        self,
    ) -> None:
        case = self.create_case(
            title="Assignment Workflow Case",
            created_by=self.administrator,
            assigned_investigator=None,
            status=Case.Status.OPEN,
        )

        self.client.force_login(
            self.administrator
        )

        response = self.client.post(
            reverse(
                "cases:case_assign",
                kwargs={
                    "case_id": case.pk,
                },
            ),
            data={
                "assigned_investigator": str(
                    self.investigator.pk
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        case.refresh_from_db()

        self.assertEqual(
            case.assigned_investigator,
            self.investigator,
        )
        self.assertEqual(
            case.status,
            Case.Status.ASSIGNED,
        )

    def test_investigator_cannot_assign_case(
        self,
    ) -> None:
        case = self.create_case(
            title="Restricted Assignment Case",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.ASSIGNED,
        )

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "cases:case_assign",
                kwargs={
                    "case_id": case.pk,
                },
            ),
            data={
                "assigned_investigator": str(
                    self.other_investigator.pk
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            403,
        )

        case.refresh_from_db()

        self.assertEqual(
            case.assigned_investigator,
            self.investigator,
        )

    # ------------------------------------------------------------------
    # Status workflow
    # ------------------------------------------------------------------

    def test_assigned_investigator_can_advance_case_status(
        self,
    ) -> None:
        case = self.create_case(
            title="Status Advance Case",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.ASSIGNED,
        )

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "cases:case_status_update",
                kwargs={
                    "case_id": case.pk,
                },
            ),
            data={
                "status": Case.Status.UNDER_INVESTIGATION,
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        case.refresh_from_db()

        self.assertEqual(
            case.status,
            Case.Status.UNDER_INVESTIGATION,
        )

    def test_invalid_case_status_jump_is_rejected(
        self,
    ) -> None:
        case = self.create_case(
            title="Invalid Status Jump Case",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.ASSIGNED,
        )

        form = CaseStatusForm(
            data={
                "status": Case.Status.AI_ANALYSIS,
            },
            instance=case,
            current_user=self.investigator,
        )

        self.assertFalse(
            form.is_valid()
        )
        self.assertIn(
            "status",
            form.errors,
        )

    def test_investigator_cannot_reopen_closed_case(
        self,
    ) -> None:
        case = self.create_case(
            title="Closed Reopen Restriction Case",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.CLOSED,
        )

        investigator_form = CaseStatusForm(
            data={
                "status": Case.Status.REPORT_GENERATION,
            },
            instance=case,
            current_user=self.investigator,
        )

        self.assertFalse(
            investigator_form.is_valid()
        )

        administrator_form = CaseStatusForm(
            data={
                "status": Case.Status.REPORT_GENERATION,
            },
            instance=case,
            current_user=self.administrator,
        )

        self.assertTrue(
            administrator_form.is_valid(),
            administrator_form.errors.as_text(),
        )

    # ------------------------------------------------------------------
    # Archive / restore
    # ------------------------------------------------------------------

    def test_archive_and_restore_return_case_to_pre_archive_status(
        self,
    ) -> None:
        case = self.create_case(
            title="Case Archive Restore Workflow",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.UNDER_INVESTIGATION,
        )

        self.client.force_login(
            self.cyber_officer
        )

        archive_response = self.client.post(
            reverse(
                "cases:case_archive",
                kwargs={
                    "case_id": case.pk,
                },
            ),
            data={
                "confirmation": "on",
                "reason": (
                    "Case archived after investigation records were "
                    "temporarily placed on administrative hold."
                ),
            },
        )

        self.assertEqual(
            archive_response.status_code,
            302,
        )

        case.refresh_from_db()

        self.assertEqual(
            case.status,
            Case.Status.ARCHIVED,
        )
        self.assertFalse(
            case.is_active
        )
        self.assertEqual(
            case.pre_archive_status,
            Case.Status.UNDER_INVESTIGATION,
        )
        self.assertEqual(
            case.archived_by,
            self.cyber_officer,
        )
        self.assertIsNotNone(
            case.archived_at
        )

        archive_reason = case.archive_reason
        archived_at = case.archived_at
        archived_by_id = case.archived_by_id

        restore_response = self.client.post(
            reverse(
                "cases:case_restore",
                kwargs={
                    "case_id": case.pk,
                },
            ),
            data={
                "confirmation": "on",
            },
        )

        self.assertEqual(
            restore_response.status_code,
            302,
        )

        case.refresh_from_db()

        self.assertTrue(
            case.is_active
        )
        self.assertEqual(
            case.status,
            Case.Status.UNDER_INVESTIGATION,
        )

        # Latest archive metadata is intentionally retained for traceability.
        self.assertEqual(
            case.archive_reason,
            archive_reason,
        )
        self.assertEqual(
            case.archived_at,
            archived_at,
        )
        self.assertEqual(
            case.archived_by_id,
            archived_by_id,
        )

    def test_investigator_cannot_archive_case(
        self,
    ) -> None:
        case = self.create_case(
            title="Archive Permission Case",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.ASSIGNED,
        )

        self.client.force_login(
            self.investigator
        )

        response = self.client.post(
            reverse(
                "cases:case_archive",
                kwargs={
                    "case_id": case.pk,
                },
            ),
            data={
                "confirmation": "on",
                "reason": (
                    "Investigator should not be permitted to archive this "
                    "case record."
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            403,
        )

        case.refresh_from_db()

        self.assertTrue(
            case.is_active
        )
        self.assertNotEqual(
            case.status,
            Case.Status.ARCHIVED,
        )

    # ------------------------------------------------------------------
    # Stale edit protection
    # ------------------------------------------------------------------

    def test_case_edit_version_detects_stale_record(
        self,
    ) -> None:
        case = self.create_case(
            title="Case Stale Edit Token",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.ASSIGNED,
        )

        token = case_views.build_case_edit_version(
            case
        )

        self.assertTrue(
            case_views.case_edit_version_matches(
                case,
                token,
            )
        )

        Case.objects.filter(
            pk=case.pk
        ).update(
            case_title="Newer Concurrent Case Title",
            updated_date=timezone.now(),
        )

        case.refresh_from_db()

        self.assertFalse(
            case_views.case_edit_version_matches(
                case,
                token,
            )
        )

    def test_stale_case_edit_post_does_not_overwrite_newer_change(
        self,
    ) -> None:
        case = self.create_case(
            title="Original Editable Case Title",
            created_by=self.investigator,
            assigned_investigator=self.investigator,
            status=Case.Status.ASSIGNED,
        )

        self.client.force_login(
            self.investigator
        )

        update_url = reverse(
            "cases:case_update",
            kwargs={
                "case_id": case.pk,
            },
        )

        get_response = self.client.get(
            update_url
        )

        self.assertEqual(
            get_response.status_code,
            200,
        )

        edit_version = get_response.context[
            "edit_version"
        ]

        Case.objects.filter(
            pk=case.pk
        ).update(
            case_title="Newer Saved Case Title",
            updated_date=timezone.now(),
        )

        stale_response = self.client.post(
            update_url,
            data={
                "edit_version": edit_version,
                "case_title": "Stale Browser Case Title",
                "description": (
                    "This stale browser submission must never overwrite the "
                    "newer case record already stored in the database."
                ),
                "crime_category": Case.CrimeCategory.PHISHING,
                "priority": Case.Priority.HIGH,
                "status": Case.Status.ASSIGNED,
            },
        )

        self.assertEqual(
            stale_response.status_code,
            302,
        )

        case.refresh_from_db()

        self.assertEqual(
            case.case_title,
            "Newer Saved Case Title",
        )