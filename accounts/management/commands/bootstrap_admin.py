"""Create or update the deployment administrator account."""

from __future__ import annotations

import os
from email.utils import parseaddr

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create or update the AIDEX administrator from environment values."

    def handle(self, *args, **options):
        username = os.getenv(
            "DJANGO_SUPERUSER_USERNAME",
            "SAKSHAM12",
        ).strip()
        password = os.getenv(
            "DJANGO_SUPERUSER_PASSWORD",
            "",
        )
        email = parseaddr(
            os.getenv("DJANGO_SUPERUSER_EMAIL", "").strip()
            or getattr(settings, "DEFAULT_FROM_EMAIL", "").strip()
            or getattr(settings, "EMAIL_HOST_USER", "").strip()
        )[1].strip()

        if not username:
            raise CommandError("DJANGO_SUPERUSER_USERNAME cannot be empty.")

        if not password:
            raise CommandError("DJANGO_SUPERUSER_PASSWORD is required.")

        if not email or email.endswith(".local"):
            raise CommandError(
                "Set DJANGO_SUPERUSER_EMAIL or DEFAULT_FROM_EMAIL to a real "
                "inbox so password-reset links can be delivered."
            )

        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": email,
                "full_name": os.getenv(
                    "DJANGO_SUPERUSER_FULL_NAME",
                    username,
                ).strip() or username,
                "badge_id": os.getenv(
                    "DJANGO_SUPERUSER_BADGE_ID",
                    f"{username}-ADMIN",
                ).strip() or f"{username}-ADMIN",
            },
        )

        user.email = email
        user.full_name = (
            os.getenv("DJANGO_SUPERUSER_FULL_NAME", "").strip()
            or user.full_name
            or username
        )
        user.badge_id = (
            os.getenv("DJANGO_SUPERUSER_BADGE_ID", "").strip()
            or user.badge_id
            or f"{username}-ADMIN"
        )
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.role = User.Role.ADMINISTRATOR
        user.account_status = User.AccountStatus.ACTIVE
        user.set_password(password)
        user.save()

        action = "created" if created else "updated"
        self.stdout.write(
            self.style.SUCCESS(
                f"Administrator {username} {action}; reset email configured."
            )
        )
