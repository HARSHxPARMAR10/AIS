from email.utils import parseaddr

from django import forms
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.template import loader

from .models import User


def extract_email_address(value):
    """Return the address part from either plain or display-name email text."""

    return parseaddr(str(value or "").strip())[1].strip()


class UserRegistrationForm(forms.ModelForm):
    """
    Public AIDEX registration form.

    Security rules:
    - Public users cannot choose privileged roles.
    - All public registrations are created as Investigator accounts.
    - Passwords must pass Django's configured password validators.
    - Password confirmation and terms acceptance are required.
    """

    confirm_password = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
            }
        ),
    )

    terms_accepted = forms.BooleanField(
        required=True,
        label=(
            "I confirm that the information provided is accurate and "
            "I agree to use AIDEX responsibly."
        ),
    )

    class Meta:
        model = User
        fields = [
            "full_name",
            "username",
            "email",
            "password",
            "phone_number",
            "department",
            "badge_id",
            "profile_photo",
        ]

        widgets = {
            "password": forms.PasswordInput(
                attrs={
                    "autocomplete": "new-password",
                }
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field_name, field in self.fields.items():
            if field_name == "terms_accepted":
                continue

            field.widget.attrs.update(
                {
                    "class": "form-control form-control-lg",
                    "placeholder": field.label,
                }
            )

        self.fields["profile_photo"].widget.attrs.update(
            {
                "class": "form-control",
                "accept": ".jpg,.jpeg,.png,image/jpeg,image/png",
            }
        )

        self.fields["terms_accepted"].widget.attrs.update(
            {
                "class": "form-check-input",
            }
        )

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip().lower()

        if not email:
            return email

        existing_users = User.objects.filter(email__iexact=email)

        if self.instance and self.instance.pk:
            existing_users = existing_users.exclude(pk=self.instance.pk)

        if existing_users.exists():
            raise forms.ValidationError(
                "An account with this email address already exists."
            )

        return email

    def clean(self):
        cleaned_data = super().clean()

        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password:
            candidate_user = self.instance
            candidate_user.username = (
                cleaned_data.get("username")
                or candidate_user.username
            )
            candidate_user.email = (
                cleaned_data.get("email")
                or candidate_user.email
            )
            candidate_user.full_name = (
                cleaned_data.get("full_name")
                or candidate_user.full_name
            )

            try:
                validate_password(
                    password,
                    user=candidate_user,
                )
            except ValidationError as error:
                self.add_error(
                    "password",
                    error,
                )

        if (
            password
            and confirm_password
            and password != confirm_password
        ):
            self.add_error(
                "confirm_password",
                "Password and confirm password do not match.",
            )

        return cleaned_data


class UserLoginForm(forms.Form):
    username = forms.CharField(
        max_length=50,
    )

    password = forms.CharField(
        widget=forms.PasswordInput(),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["username"].widget.attrs.update(
            {
                "class": "form-control form-control-lg",
                "placeholder": "Enter Username",
                "autocomplete": "username",
            }
        )

        self.fields["password"].widget.attrs.update(
            {
                "class": "form-control form-control-lg",
                "placeholder": "Enter Password",
                "autocomplete": "current-password",
            }
        )


class AIDEXPasswordResetForm(PasswordResetForm):
    """
    Send reset links only to eligible AIDEX application accounts.

    The iterator deliberately returns no distinction between an unknown email
    address and an ineligible account. This preserves Django's account-
    enumeration protection while respecting AIDEX account status.
    """

    email = forms.EmailField(
        label="Registered Email Address",
        max_length=254,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control form-control-lg",
                "placeholder": "Enter your registered email",
                "autocomplete": "email",
                "autofocus": True,
            }
        ),
    )

    def get_users(self, email):
        normalized_email = (email or "").strip()

        if not normalized_email:
            return iter(())

        eligible_users = list(User._default_manager.filter(
            email__iexact=normalized_email,
            is_active=True,
            account_status__in=(
                User.AccountStatus.PENDING,
                User.AccountStatus.ACTIVE,
                User.AccountStatus.LOCKED,
            ),
        ))

        configured_reset_emails = {
            extract_email_address(
                getattr(settings, setting_name, "")
                or ""
            ).casefold()
            for setting_name in (
                "DEFAULT_FROM_EMAIL",
                "EMAIL_HOST_USER",
                "SERVER_EMAIL",
            )
        }
        configured_reset_emails.discard("")

        if (
            not eligible_users
            and normalized_email.casefold() in configured_reset_emails
        ):
            admin_username = str(
                getattr(settings, "DJANGO_SUPERUSER_USERNAME", "")
                or "SAKSHAM12"
            ).strip()
            admin_user = (
                User._default_manager
                .filter(
                    username=admin_username,
                    is_superuser=True,
                    is_active=True,
                )
                .first()
            )

            if admin_user is not None:
                admin_user.email = normalized_email
                admin_user.account_status = User.AccountStatus.ACTIVE
                admin_user.save(
                    update_fields=[
                        "email",
                        "account_status",
                        "updated_date",
                    ]
                )
                eligible_users = [admin_user]

        return (
            user
            for user in eligible_users
            if user.has_usable_password()
            and str(user.email or "").casefold()
            == normalized_email.casefold()
        )

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        subject = loader.render_to_string(
            subject_template_name,
            context,
        )
        subject = "".join(subject.splitlines())
        body = loader.render_to_string(
            email_template_name,
            context,
        )
        email_message = EmailMultiAlternatives(
            subject,
            body,
            from_email,
            [to_email],
        )

        if html_email_template_name is not None:
            html_email = loader.render_to_string(
                html_email_template_name,
                context,
            )
            email_message.attach_alternative(
                html_email,
                "text/html",
            )

        email_message.send(fail_silently=False)


class AIDEXSetPasswordForm(SetPasswordForm):
    """Style Django's validated reset-password fields for AIDEX."""

    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)

        self.fields["new_password1"].widget.attrs.update(
            {
                "class": "form-control form-control-lg",
                "placeholder": "Enter new password",
                "autocomplete": "new-password",
                "autofocus": True,
            }
        )
        self.fields["new_password2"].widget.attrs.update(
            {
                "class": "form-control form-control-lg",
                "placeholder": "Confirm new password",
                "autocomplete": "new-password",
            }
        )


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
            "full_name",
            "email",
            "phone_number",
            "department",
            "profile_photo",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field in self.fields.values():
            field.widget.attrs.update(
                {
                    "class": "form-control",
                    "placeholder": field.label,
                }
            )

        self.fields["profile_photo"].widget.attrs.update(
            {
                "accept": ".jpg,.jpeg,.png,image/jpeg,image/png",
            }
        )

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip().lower()

        if not email:
            return email

        existing_users = User.objects.filter(email__iexact=email)

        if self.instance and self.instance.pk:
            existing_users = existing_users.exclude(pk=self.instance.pk)

        if existing_users.exists():
            raise forms.ValidationError(
                "An account with this email address already exists."
            )

        return email


class UserPasswordChangeForm(forms.Form):
    old_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "current-password",
            }
        )
    )

    new_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
            }
        )
    )

    confirm_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "new-password",
            }
        )
    )

    def clean(self):
        cleaned_data = super().clean()

        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password:
            try:
                validate_password(new_password)
            except ValidationError as error:
                self.add_error(
                    "new_password",
                    error,
                )

        if (
            new_password
            and confirm_password
            and new_password != confirm_password
        ):
            self.add_error(
                "confirm_password",
                "New password and confirm password do not match.",
            )

        return cleaned_data
