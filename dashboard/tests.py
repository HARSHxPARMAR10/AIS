"""Regression tests for AIDEX role-aware dashboards."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


User = get_user_model()


class DashboardAccessTests(TestCase):
    password = "StrongDashboardPassword123!"

    @classmethod
    def setUpTestData(cls) -> None:
        cls.administrator = User.objects.create_user(
            username="dashboardadmin",
            email="dashboardadmin@example.com",
            password=cls.password,
            full_name="Dashboard Administrator",
            badge_id="DSH-ADM-001",
            role=User.Role.ADMINISTRATOR,
            account_status=User.AccountStatus.ACTIVE,
        )
        cls.investigator = User.objects.create_user(
            username="dashboardinvestigator",
            email="dashboardinvestigator@example.com",
            password=cls.password,
            full_name="Dashboard Investigator",
            badge_id="DSH-INV-001",
            role=User.Role.INVESTIGATOR,
            account_status=User.AccountStatus.ACTIVE,
        )
        cls.cyber_officer = User.objects.create_user(
            username="dashboardofficer",
            email="dashboardofficer@example.com",
            password=cls.password,
            full_name="Dashboard Cyber Officer",
            badge_id="DSH-CYB-001",
            role=User.Role.CYBER_OFFICER,
            account_status=User.AccountStatus.ACTIVE,
        )

    def test_anonymous_dashboard_redirects_to_login(self) -> None:
        response = self.client.get(reverse("dashboard:dashboard_redirect"))
        self.assertRedirects(
            response,
            f"{reverse('accounts:login')}?next={reverse('dashboard:dashboard_redirect')}",
        )

    def test_each_role_is_redirected_to_its_dashboard(self) -> None:
        expected = (
            (self.administrator, "dashboard:admin_dashboard"),
            (self.investigator, "dashboard:investigator_dashboard"),
            (self.cyber_officer, "dashboard:cyber_officer_dashboard"),
        )

        for user, route_name in expected:
            with self.subTest(role=user.role):
                self.client.force_login(user)
                response = self.client.get(
                    reverse("dashboard:dashboard_redirect")
                )
                self.assertRedirects(response, reverse(route_name))
                self.client.logout()

    def test_each_role_dashboard_renders(self) -> None:
        expected = (
            (self.administrator, "dashboard:admin_dashboard"),
            (self.investigator, "dashboard:investigator_dashboard"),
            (self.cyber_officer, "dashboard:cyber_officer_dashboard"),
        )

        for user, route_name in expected:
            with self.subTest(role=user.role):
                self.client.force_login(user)
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "AIDEX")
                self.client.logout()

    def test_wrong_role_cannot_open_administrator_dashboard(self) -> None:
        self.client.force_login(self.investigator)
        response = self.client.get(reverse("dashboard:admin_dashboard"))
        self.assertEqual(response.status_code, 403)

