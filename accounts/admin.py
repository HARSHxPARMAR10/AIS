"""
AIDEX Accounts Django Admin

Security design:
- Django /admin/ user management is available only to real superusers.
- Investigator, Cyber Officer and normal AIDEX Administrator accounts cannot
  grant themselves Django staff/superuser privileges.
- Staff/superuser fields are not editable through this admin.
- Superusers are always preserved as AIDEX Administrators.
- User deletion is disabled; account deactivation should be used instead.
"""

from __future__ import annotations

from typing import Any

from django import forms
from django.contrib import admin, messages
from django.contrib.auth import password_validation
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from .models import User


class AIDEXAdminUserCreationForm(
    forms.ModelForm
):
    """
    Safe Django-Admin form for creating normal AIDEX accounts.

    Creating Django superusers remains a command-line operation:
        python manage.py createsuperuser
    """

    password1 = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
            }
        ),
        help_text=password_validation.password_validators_help_text_html(),
    )

    password2 = forms.CharField(
        label="Password confirmation",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
            }
        ),
        help_text=(
            "Enter the same password again for verification."
        ),
    )

    class Meta:
        model = User

        fields = (
            "username",
            "full_name",
            "email",
            "badge_id",
            "phone_number",
            "department",
            "role",
            "account_status",
            "is_active",
        )

    def clean_password2(
        self,
    ) -> str:
        password1 = self.cleaned_data.get(
            "password1"
        )

        password2 = self.cleaned_data.get(
            "password2"
        )

        if (
            password1
            and password2
            and password1 != password2
        ):
            raise forms.ValidationError(
                "The two password fields do not match."
            )

        if password2:
            password_validation.validate_password(
                password2,
                self.instance,
            )

        return password2

    def save(
        self,
        commit: bool = True,
    ) -> User:
        user = super().save(
            commit=False
        )

        user.set_password(
            self.cleaned_data[
                "password1"
            ]
        )

        # Accounts created from Django Admin are still ordinary application
        # users. The model also enforces this boundary as a backstop.
        user.is_staff = False
        user.is_superuser = False

        if commit:
            user.save()
            self.save_m2m()

        return user


class AIDEXAdminUserChangeForm(
    forms.ModelForm
):
    """
    Safe change form that never exposes raw password editing.
    """

    password = ReadOnlyPasswordHashField(
        label=_("Password"),
        help_text=_(
            "Passwords are not stored in raw form, so there is no way "
            "to see this user's password."
        ),
    )

    class Meta:
        model = User
        fields = "__all__"

    def clean_password(
        self,
    ) -> str:
        return self.initial.get(
            "password",
            ""
        )


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    """
    Superuser-only administration for AIDEX accounts.
    """

    form = AIDEXAdminUserChangeForm
    add_form = AIDEXAdminUserCreationForm

    list_display = (
        "username",
        "full_name",
        "email",
        "role",
        "account_status",
        "is_active",
        "django_admin_access",
    )

    list_filter = (
        "role",
        "account_status",
        "is_active",
    )

    search_fields = (
        "username",
        "full_name",
        "email",
        "badge_id",
    )

    ordering = (
        "username",
    )

    readonly_fields = (
        "last_login",
        "date_joined",
        "updated_date",
        "failed_login_count",
        "locked_until",
        "is_staff",
        "is_superuser",
    )

    fieldsets = (
        (
            None,
            {
                "fields": (
                    "username",
                    "password",
                ),
            },
        ),
        (
            "AIDEX Identity",
            {
                "fields": (
                    "full_name",
                    "email",
                    "badge_id",
                    "phone_number",
                    "department",
                    "profile_photo",
                ),
            },
        ),
        (
            "AIDEX Access",
            {
                "fields": (
                    "role",
                    "account_status",
                    "is_active",
                ),
            },
        ),
        (
            "Django Administrative Privileges",
            {
                "description": (
                    "These fields are security-controlled. "
                    "AIDEX roles do not grant Django Admin access."
                ),
                "fields": (
                    "is_staff",
                    "is_superuser",
                ),
            },
        ),
        (
            "Login Security",
            {
                "fields": (
                    "failed_login_count",
                    "locked_until",
                    "last_login",
                ),
            },
        ),
        (
            "Important Dates",
            {
                "fields": (
                    "date_joined",
                    "updated_date",
                ),
            },
        ),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": (
                    "wide",
                ),
                "fields": (
                    "username",
                    "full_name",
                    "email",
                    "badge_id",
                    "phone_number",
                    "department",
                    "role",
                    "account_status",
                    "is_active",
                    "password1",
                    "password2",
                ),
            },
        ),
    )

    actions = (
        "activate_accounts",
        "deactivate_accounts",
        "clear_login_lock",
    )

    @admin.display(
        boolean=True,
        description="Django admin",
    )
    def django_admin_access(
        self,
        obj: User,
    ) -> bool:
        return obj.has_django_admin_access

    def get_readonly_fields(
        self,
        request: HttpRequest,
        obj: User | None = None,
    ) -> tuple[str, ...]:
        """
        Prevent privilege fields from being edited.

        A superuser object's AIDEX role, account state and activation state
        are also locked because the model requires that trusted account to
        remain an active Administrator.
        """

        readonly = list(
            super().get_readonly_fields(
                request,
                obj,
            )
        )

        if (
            obj is not None
            and obj.is_superuser
        ):
            readonly.extend([
                "role",
                "account_status",
                "is_active",
            ])

        return tuple(
            dict.fromkeys(
                readonly
            )
        )

    def has_module_permission(
        self,
        request: HttpRequest,
    ) -> bool:
        return bool(
            request.user.is_authenticated
            and request.user.is_active
            and request.user.is_superuser
        )

    def has_view_permission(
        self,
        request: HttpRequest,
        obj: User | None = None,
    ) -> bool:
        return bool(
            request.user.is_authenticated
            and request.user.is_active
            and request.user.is_superuser
        )

    def has_add_permission(
        self,
        request: HttpRequest,
    ) -> bool:
        return bool(
            request.user.is_authenticated
            and request.user.is_active
            and request.user.is_superuser
        )

    def has_change_permission(
        self,
        request: HttpRequest,
        obj: User | None = None,
    ) -> bool:
        return bool(
            request.user.is_authenticated
            and request.user.is_active
            and request.user.is_superuser
        )

    def has_delete_permission(
        self,
        request: HttpRequest,
        obj: User | None = None,
    ) -> bool:
        """
        Do not permanently delete identity records through Django Admin.
        """

        return False

    def save_model(
        self,
        request: HttpRequest,
        obj: User,
        form: forms.ModelForm,
        change: bool,
    ) -> None:
        """
        Preserve the Django-admin privilege boundary on every admin save.
        """

        if not request.user.is_superuser:
            raise forms.ValidationError(
                "Only a Django superuser may manage AIDEX accounts here."
            )

        if obj.is_superuser:
            obj.role = (
                User.Role.ADMINISTRATOR
            )
            obj.account_status = (
                User.AccountStatus.ACTIVE
            )
            obj.is_active = True
            obj.is_staff = True

        else:
            obj.is_staff = False
            obj.is_superuser = False

        super().save_model(
            request,
            obj,
            form,
            change,
        )

    @admin.action(
        description="Activate selected AIDEX accounts",
    )
    def activate_accounts(
        self,
        request: HttpRequest,
        queryset,
    ) -> None:
        """
        Approve selected non-superuser accounts.
        """

        eligible = queryset.filter(
            is_superuser=False
        )

        updated = eligible.update(
            account_status=(
                User.AccountStatus.ACTIVE
            ),
            is_active=True,
            is_staff=False,
            failed_login_count=0,
            locked_until=None,
        )

        self.message_user(
            request,
            (
                f"{updated} account(s) activated successfully."
            ),
            level=messages.SUCCESS,
        )

    @admin.action(
        description="Deactivate selected AIDEX accounts",
    )
    def deactivate_accounts(
        self,
        request: HttpRequest,
        queryset,
    ) -> None:
        """
        Deactivate selected non-superuser accounts without deleting them.
        """

        eligible = queryset.filter(
            is_superuser=False
        )

        updated = eligible.update(
            account_status=(
                User.AccountStatus.DEACTIVATED
            ),
            is_active=False,
            is_staff=False,
            is_superuser=False,
        )

        self.message_user(
            request,
            (
                f"{updated} account(s) deactivated."
            ),
            level=messages.WARNING,
        )

    @admin.action(
        description="Clear selected account login locks",
    )
    def clear_login_lock(
        self,
        request: HttpRequest,
        queryset,
    ) -> None:
        """
        Clear failed-login counters without silently activating suspended or
        deactivated accounts.
        """

        eligible = queryset.filter(
            is_superuser=False
        )

        updated = eligible.update(
            failed_login_count=0,
            locked_until=None,
        )

        self.message_user(
            request,
            (
                f"Login lock data cleared for {updated} account(s)."
            ),
            level=messages.SUCCESS,
        )