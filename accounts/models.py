"""
AIDEX Accounts Models

Custom user model for AIDEX.

Security policy:
- Public/normal application users are never Django staff users.
- Investigator and Cyber Officer accounts cannot become Django superusers.
- AIDEX Administrator is an application role and does not automatically grant
  access to Django's /admin/ site.
- Only an actual Django superuser may use Django Admin.
- Every Django superuser is forced to the AIDEX Administrator role and Active
  account status.

Use:
    python manage.py createsuperuser

to create the trusted Django administrative account.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models


ROLE_ADMINISTRATOR = "ADMINISTRATOR"
ROLE_INVESTIGATOR = "INVESTIGATOR"
ROLE_CYBER_OFFICER = "CYBER_OFFICER"

STATUS_PENDING = "PENDING"
STATUS_ACTIVE = "ACTIVE"


class AIDEXUserManager(UserManager):
    """
    User manager with safe defaults for normal users and superusers.
    """

    def create_user(
        self,
        username: str,
        email: str | None = None,
        password: str | None = None,
        **extra_fields: Any,
    ):
        """
        Create a normal AIDEX application user.

        Normal users must not receive Django staff/superuser privileges.
        """

        extra_fields.setdefault(
            "is_staff",
            False,
        )
        extra_fields.setdefault(
            "is_superuser",
            False,
        )

        if extra_fields.get("is_staff"):
            raise ValueError(
                (
                    "Normal AIDEX users cannot be created with "
                    "Django staff access."
                )
            )

        if extra_fields.get("is_superuser"):
            raise ValueError(
                (
                    "Normal AIDEX users cannot be created as "
                    "Django superusers."
                )
            )

        return super().create_user(
            username=username,
            email=email,
            password=password,
            **extra_fields,
        )

    def create_superuser(
        self,
        username: str,
        email: str | None = None,
        password: str | None = None,
        **extra_fields: Any,
    ):
        """
        Create the trusted Django administrative account.

        A Django superuser is always an AIDEX Administrator with an
        ACTIVE account.
        """

        extra_fields["is_staff"] = True
        extra_fields["is_superuser"] = True
        extra_fields["is_active"] = True
        extra_fields["role"] = ROLE_ADMINISTRATOR
        extra_fields["account_status"] = STATUS_ACTIVE

        return super().create_superuser(
            username=username,
            email=email,
            password=password,
            **extra_fields,
        )


class User(AbstractUser):
    """
    AIDEX custom user.

    Important distinction:
        role
            Controls permissions inside the AIDEX application.

        is_staff / is_superuser
            Controls Django Admin privileges.

    Merely changing role to ADMINISTRATOR must never grant Django Admin access.
    """

    class Role(models.TextChoices):
        ADMINISTRATOR = (
            ROLE_ADMINISTRATOR,
            "Administrator",
        )
        INVESTIGATOR = (
            ROLE_INVESTIGATOR,
            "Investigator",
        )
        CYBER_OFFICER = (
            ROLE_CYBER_OFFICER,
            "Cyber Officer",
        )

    class AccountStatus(models.TextChoices):
        PENDING = "PENDING", "Pending"
        ACTIVE = "ACTIVE", "Active"
        LOCKED = "LOCKED", "Locked"
        SUSPENDED = "SUSPENDED", "Suspended"
        DEACTIVATED = "DEACTIVATED", "Deactivated"

    full_name = models.CharField(
        max_length=150,
    )

    email = models.EmailField(
        unique=True,
    )

    phone_number = models.CharField(
        max_length=15,
        blank=True,
    )

    department = models.CharField(
        max_length=100,
        blank=True,
    )

    badge_id = models.CharField(
        max_length=50,
        unique=True,
    )

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.INVESTIGATOR,
    )

    profile_photo = models.ImageField(
        upload_to="profile_photos/",
        blank=True,
        null=True,
    )

    account_status = models.CharField(
        max_length=20,
        choices=AccountStatus.choices,
        default=AccountStatus.PENDING,
    )

    failed_login_count = models.PositiveSmallIntegerField(
        default=0,
    )

    locked_until = models.DateTimeField(
        blank=True,
        null=True,
    )

    updated_date = models.DateTimeField(
        auto_now=True,
    )

    objects = AIDEXUserManager()

    REQUIRED_FIELDS = [
        "email",
        "full_name",
        "badge_id",
    ]

    def __str__(self) -> str:
        return (
            f"{self.username} - "
            f"{self.get_role_display()}"
        )

    @property
    def is_account_active(self) -> bool:
        """
        Return whether the account may be treated as active by AIDEX.
        """

        return (
            self.account_status
            == self.AccountStatus.ACTIVE
            and self.is_active
        )

    @property
    def has_django_admin_access(self) -> bool:
        """
        Return whether this account is trusted for Django Admin access.
        """

        return bool(
            self.is_active
            and self.is_staff
            and self.is_superuser
            and self.role
            == self.Role.ADMINISTRATOR
            and self.account_status
            == self.AccountStatus.ACTIVE
        )

    def _enforce_privilege_invariants(
        self,
    ) -> set[str]:
        """
        Enforce the boundary between AIDEX roles and Django privileges.

        Returns field names changed by the safety policy so save(update_fields)
        can persist those changes as well.
        """

        changed_fields: set[str] = set()

        if self.is_superuser:
            if self.role != self.Role.ADMINISTRATOR:
                self.role = self.Role.ADMINISTRATOR
                changed_fields.add(
                    "role"
                )

            if not self.is_staff:
                self.is_staff = True
                changed_fields.add(
                    "is_staff"
                )

            if not self.is_active:
                self.is_active = True
                changed_fields.add(
                    "is_active"
                )

            if (
                self.account_status
                != self.AccountStatus.ACTIVE
            ):
                self.account_status = (
                    self.AccountStatus.ACTIVE
                )
                changed_fields.add(
                    "account_status"
                )

            if self.failed_login_count != 0:
                self.failed_login_count = 0
                changed_fields.add(
                    "failed_login_count"
                )

            if self.locked_until is not None:
                self.locked_until = None
                changed_fields.add(
                    "locked_until"
                )

            return changed_fields

        # All non-superuser AIDEX accounts, including the application-level
        # Administrator role, are kept out of Django Admin.
        if self.is_staff:
            self.is_staff = False
            changed_fields.add(
                "is_staff"
            )

        return changed_fields

    def save(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Save the user while enforcing privilege invariants.

        The update_fields handling is important: callers sometimes save only
        one field. Any safety field changed above must still reach the DB.
        """

        safety_fields = (
            self._enforce_privilege_invariants()
        )

        update_fields = kwargs.get(
            "update_fields"
        )

        if (
            update_fields is not None
            and safety_fields
        ):
            kwargs[
                "update_fields"
            ] = set(
                update_fields
            ) | safety_fields

        super().save(
            *args,
            **kwargs,
        )