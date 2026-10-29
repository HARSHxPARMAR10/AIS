"""
AIDEX account-login security regression tests.

Coverage:
- failed-login threshold locking
- successful login counter reset
- expired temporary lock release
- stale authenticate() result cannot bypass a concurrent account lock
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import views as account_views


User = get_user_model()


class AccountLoginSecurityRegressionTests(TestCase):
    def setUp(self) -> None:
        self.password = "StrongTestPassword123!"

        self.user = User.objects.create_user(
            username="loginsecurityuser",
            email="loginsecurity@example.com",
            password=self.password,
            full_name="Login Security User",
            badge_id="LOGIN-SEC-001",
            role=User.Role.INVESTIGATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

    def test_failed_login_threshold_locks_account(
        self,
    ) -> None:
        for _ in range(
            account_views.MAX_FAILED_LOGIN_ATTEMPTS
        ):
            account_views._record_failed_login(
                self.user.username
            )

        self.user.refresh_from_db()

        self.assertEqual(
            self.user.account_status,
            User.AccountStatus.LOCKED,
        )
        self.assertGreaterEqual(
            self.user.failed_login_count,
            account_views.MAX_FAILED_LOGIN_ATTEMPTS,
        )
        self.assertIsNotNone(
            self.user.locked_until
        )

    def test_successful_login_resets_failed_counter(
        self,
    ) -> None:
        User.objects.filter(
            pk=self.user.pk
        ).update(
            failed_login_count=3,
            updated_date=timezone.now(),
        )

        response = self.client.post(
            reverse(
                "accounts:login"
            ),
            data={
                "username": self.user.username,
                "password": self.password,
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.user.refresh_from_db()

        self.assertEqual(
            self.user.account_status,
            User.AccountStatus.ACTIVE,
        )
        self.assertEqual(
            self.user.failed_login_count,
            0,
        )
        self.assertIsNone(
            self.user.locked_until
        )

        self.assertEqual(
            str(
                self.client.session.get(
                    "_auth_user_id"
                )
            ),
            str(self.user.pk),
        )

    def test_expired_temporary_lock_is_released(
        self,
    ) -> None:
        expired_at = (
            timezone.now()
            - timedelta(
                minutes=1
            )
        )

        User.objects.filter(
            pk=self.user.pk
        ).update(
            account_status=User.AccountStatus.LOCKED,
            failed_login_count=(
                account_views.MAX_FAILED_LOGIN_ATTEMPTS
            ),
            locked_until=expired_at,
            updated_date=timezone.now(),
        )

        user = account_views._get_login_user(
            self.user.username
        )

        user = account_views._unlock_expired_temporary_lock(
            user
        )

        self.assertEqual(
            user.account_status,
            User.AccountStatus.ACTIVE,
        )
        self.assertEqual(
            user.failed_login_count,
            0,
        )
        self.assertIsNone(
            user.locked_until
        )

    def test_stale_authenticate_result_cannot_bypass_concurrent_lock(
        self,
    ) -> None:
        """
        Simulate authenticate() reading ACTIVE, followed by another request
        locking the same account before the login session is created.
        """

        stale_authenticated_user = User.objects.get(
            pk=self.user.pk
        )

        def authenticate_then_concurrently_lock(
            *args,
            **kwargs,
        ):
            lock_until = (
                timezone.now()
                + timedelta(
                    minutes=account_views.LOGIN_LOCK_MINUTES
                )
            )

            User.objects.filter(
                pk=self.user.pk
            ).update(
                account_status=User.AccountStatus.LOCKED,
                failed_login_count=(
                    account_views.MAX_FAILED_LOGIN_ATTEMPTS
                ),
                locked_until=lock_until,
                updated_date=timezone.now(),
            )

            return stale_authenticated_user

        with patch(
            "accounts.views.authenticate",
            side_effect=authenticate_then_concurrently_lock,
        ):
            response = self.client.post(
                reverse(
                    "accounts:login"
                ),
                data={
                    "username": self.user.username,
                    "password": self.password,
                },
            )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.user.refresh_from_db()

        self.assertEqual(
            self.user.account_status,
            User.AccountStatus.LOCKED,
        )
        self.assertIsNone(
            self.client.session.get(
                "_auth_user_id"
            )
        )


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class PasswordResetTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            username="passwordresetuser",
            email="passwordreset@example.com",
            password="OldStrongPassword123!",
            full_name="Password Reset User",
            badge_id="RESET-SEC-001",
            role=User.Role.INVESTIGATOR,
            account_status=User.AccountStatus.ACTIVE,
        )

    def test_reset_email_is_sent_to_registered_email(self) -> None:
        response = self.client.post(
            reverse("accounts:password_reset"),
            {"email": self.user.email},
        )

        self.assertRedirects(
            response,
            reverse("accounts:password_reset_done"),
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.user.email])
        self.assertIn("/accounts/reset-password/", mail.outbox[0].body)

    def test_reset_link_changes_password(self) -> None:
        self.client.post(
            reverse("accounts:password_reset"),
            {"email": self.user.email},
        )

        message = mail.outbox[0]
        reset_url = message.body.split("http://testserver", 1)[1].splitlines()[0]
        response = self.client.get(reset_url, follow=True)
        self.assertEqual(response.status_code, 200)

        set_password_url = response.redirect_chain[-1][0]
        response = self.client.post(
            set_password_url,
            {
                "new_password1": "K9v#Q2m!Lp7Z",
                "new_password2": "K9v#Q2m!Lp7Z",
            },
        )

        if response.status_code == 200:
            self.fail(response.context["form"].errors.as_text())
        self.assertRedirects(
            response,
            reverse("accounts:password_reset_complete"),
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("K9v#Q2m!Lp7Z"))