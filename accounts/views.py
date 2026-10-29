from datetime import timedelta
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Case, F, Value, When
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_POST

from .forms import (
    AIDEXPasswordResetForm,
    AIDEXSetPasswordForm,
    UserLoginForm,
    UserProfileForm,
    UserRegistrationForm,
)
from .models import User


logger = logging.getLogger(__name__)


MAX_FAILED_LOGIN_ATTEMPTS = int(
    getattr(
        settings,
        "AIDEX_MAX_FAILED_LOGIN_ATTEMPTS",
        5,
    )
)

LOGIN_LOCK_MINUTES = int(
    getattr(
        settings,
        "AIDEX_LOGIN_LOCK_MINUTES",
        15,
    )
)


class AIDEXPasswordResetView(auth_views.PasswordResetView):
    form_class = AIDEXPasswordResetForm
    template_name = "accounts/password_reset_form.html"
    email_template_name = "accounts/password_reset_email.txt"
    html_email_template_name = "accounts/password_reset_email.html"
    subject_template_name = "accounts/password_reset_subject.txt"
    success_url = reverse_lazy("accounts:password_reset_done")

    def form_valid(self, form):
        try:
            return super().form_valid(form)
        except Exception as exc:
            logger.exception(
                "AIDEX password reset email delivery failed."
            )
            form.add_error(
                None,
                (
                    "Password reset email could not be sent. Ask the "
                    "administrator to verify Render SMTP environment "
                    "variables and the Gmail app password."
                ),
            )
            messages.error(
                self.request,
                "Password reset email delivery failed.",
            )
            return self.form_invalid(form)


class AIDEXPasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = "accounts/password_reset_done.html"


class AIDEXPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    form_class = AIDEXSetPasswordForm
    template_name = "accounts/password_reset_confirm.html"
    success_url = reverse_lazy("accounts:password_reset_complete")
    post_reset_login = False

    def form_valid(self, form):
        response = super().form_valid(form)
        user = form.user

        if user.account_status == User.AccountStatus.LOCKED:
            User.objects.filter(pk=user.pk).update(
                account_status=User.AccountStatus.ACTIVE,
                failed_login_count=0,
                locked_until=None,
                updated_date=timezone.now(),
            )

        return response


class AIDEXPasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = "accounts/password_reset_complete.html"


def _get_login_user(username):
    """
    Find an AIDEX user for login-security bookkeeping.

    Authentication itself is still performed by Django's
    authenticate() function.
    """
    username = (username or "").strip()

    if not username:
        return None

    return (
        User.objects
        .filter(username__iexact=username)
        .first()
    )


def _unlock_expired_temporary_lock(user):
    """
    Automatically release an expired temporary login lock with one atomic
    conditional UPDATE.

    SQLite ignores select_for_update(), so lifecycle correctness must not rely
    on row locks here.
    """
    if user is None:
        return None

    now = timezone.now()

    if (
        user.account_status != User.AccountStatus.LOCKED
        or user.locked_until is None
        or user.locked_until > now
    ):
        return user

    User.objects.filter(
        pk=user.pk,
        is_superuser=False,
        account_status=User.AccountStatus.LOCKED,
        locked_until__isnull=False,
        locked_until__lte=now,
    ).update(
        account_status=User.AccountStatus.ACTIVE,
        failed_login_count=0,
        locked_until=None,
        updated_date=now,
    )

    user.refresh_from_db()
    return user


def _record_failed_login(username):
    """
    Atomically record one failed login attempt for an existing ACTIVE account.

    The increment and threshold decision happen in a single SQL UPDATE using
    F()/Case expressions, so simultaneous failures cannot lose increments on
    SQLite.

    Django superusers are excluded because the User model intentionally keeps
    trusted superuser accounts ACTIVE and clears application-level lock state.
    """
    username = (username or "").strip()

    if not username:
        return {
            "locked": False,
            "locked_until": None,
        }

    user = (
        User.objects
        .filter(username__iexact=username)
        .first()
    )

    if user is None:
        return {
            "locked": False,
            "locked_until": None,
        }

    if user.is_superuser:
        return {
            "locked": False,
            "locked_until": None,
        }

    now = timezone.now()

    # Release an expired temporary lock first, if this exact account still
    # carries that expired temporary lock.
    User.objects.filter(
        pk=user.pk,
        is_superuser=False,
        account_status=User.AccountStatus.LOCKED,
        locked_until__isnull=False,
        locked_until__lte=now,
    ).update(
        account_status=User.AccountStatus.ACTIVE,
        failed_login_count=0,
        locked_until=None,
        updated_date=now,
    )

    threshold = max(
        0,
        MAX_FAILED_LOGIN_ATTEMPTS - 1,
    )

    lock_until = (
        now
        + timedelta(
            minutes=LOGIN_LOCK_MINUTES,
        )
    )

    # One atomic UPDATE decides whether this failure reaches the lock
    # threshold. Each concurrent request evaluates F("failed_login_count")
    # against the database value at its own serialized write point.
    User.objects.filter(
        pk=user.pk,
        is_superuser=False,
        is_active=True,
        account_status=User.AccountStatus.ACTIVE,
    ).update(
        failed_login_count=F("failed_login_count") + 1,
        account_status=Case(
            When(
                failed_login_count__gte=threshold,
                then=Value(
                    User.AccountStatus.LOCKED
                ),
            ),
            default=F("account_status"),
        ),
        locked_until=Case(
            When(
                failed_login_count__gte=threshold,
                then=Value(
                    lock_until
                ),
            ),
            default=F("locked_until"),
        ),
        updated_date=now,
    )

    user.refresh_from_db()

    return {
        "locked": (
            user.account_status
            == User.AccountStatus.LOCKED
        ),
        "locked_until": user.locked_until,
    }


def _claim_successful_login_state(user):
    """
    Atomically claim permission to complete a successful login.

    authenticate() returns a Python User object, but the account can be locked
    by another failed-login request immediately afterwards. This conditional
    UPDATE succeeds only if the database still says the account is ACTIVE at
    the exact login handoff point.

    Returning False means the authentication result became stale and no
    session must be created.
    """

    if user is None:
        return False

    if user.is_superuser:
        user.refresh_from_db()

        return bool(
            user.is_active
            and user.is_superuser
            and user.account_status
            == User.AccountStatus.ACTIVE
        )

    now = timezone.now()

    updated_rows = (
        User.objects
        .filter(
            pk=user.pk,
            is_superuser=False,
            is_active=True,
            account_status=User.AccountStatus.ACTIVE,
        )
        .update(
            failed_login_count=0,
            locked_until=None,
            updated_date=now,
        )
    )

    user.refresh_from_db()

    return updated_rows == 1


def register_view(request):
    """
    Register a new public AIDEX user.

    Security rules:
    - Public users are always registered as Investigators.
    - New public accounts start in PENDING status.
    - Administrator/Cyber Officer roles cannot be granted here.
    """

    if request.user.is_authenticated:
        return redirect(
            "accounts:dashboard_redirect"
        )

    if request.method == "POST":
        form = UserRegistrationForm(
            request.POST,
            request.FILES,
        )

        if form.is_valid():
            user = form.save(commit=False)

            user.role = User.Role.INVESTIGATOR
            user.account_status = User.AccountStatus.PENDING

            # Authentication can verify credentials for a pending
            # AIDEX account, while account_status blocks application login.
            user.is_active = True
            user.is_staff = False
            user.is_superuser = False

            user.failed_login_count = 0
            user.locked_until = None

            user.set_password(
                form.cleaned_data["password"]
            )

            user.save()

            messages.success(
                request,
                (
                    "Registration submitted successfully. "
                    "Your Investigator account is waiting for "
                    "administrator approval before you can log in."
                ),
            )

            return redirect(
                "accounts:login"
            )
    else:
        form = UserRegistrationForm()

    return render(
        request,
        "accounts/register.html",
        {
            "form": form,
        },
    )


def login_view(request):
    """
    Authenticate an AIDEX user with failed-login protection.

    Default protection:
    - 5 consecutive invalid password attempts
    - 15 minute temporary account lock

    Defaults can later be overridden in settings.py using:
    AIDEX_MAX_FAILED_LOGIN_ATTEMPTS
    AIDEX_LOGIN_LOCK_MINUTES
    """

    if request.user.is_authenticated:
        return redirect(
            "accounts:dashboard_redirect"
        )

    form = UserLoginForm(
        request.POST or None
    )

    if (
        request.method == "POST"
        and form.is_valid()
    ):
        username = (
            form.cleaned_data["username"]
            .strip()
        )

        password = form.cleaned_data["password"]

        candidate_user = _get_login_user(
            username
        )

        candidate_user = (
            _unlock_expired_temporary_lock(
                candidate_user
            )
        )

        # Temporary or administrator/manual lock.
        if (
            candidate_user is not None
            and candidate_user.account_status
            == User.AccountStatus.LOCKED
        ):
            if (
                candidate_user.locked_until
                and candidate_user.locked_until
                > timezone.now()
            ):
                messages.error(
                    request,
                    (
                        "Your account is temporarily locked due to "
                        "multiple failed login attempts. Please try "
                        "again after the lock period expires."
                    ),
                )
            else:
                messages.error(
                    request,
                    (
                        "Your account is locked. "
                        "Please contact an administrator."
                    ),
                )

            return render(
                request,
                "accounts/login.html",
                {
                    "form": form,
                },
            )

        user = authenticate(
            request,
            username=username,
            password=password,
        )

        if user is None:
            failure_state = _record_failed_login(
                username
            )

            if failure_state["locked"]:
                messages.error(
                    request,
                    (
                        "Too many failed login attempts. "
                        f"Your account has been locked for "
                        f"{LOGIN_LOCK_MINUTES} minutes."
                    ),
                )
            else:
                messages.error(
                    request,
                    "Invalid username or password.",
                )

        elif not user.is_active:
            messages.error(
                request,
                "Your account is inactive.",
            )

        elif (
            user.account_status
            == User.AccountStatus.SUSPENDED
        ):
            messages.error(
                request,
                "Your account has been suspended.",
            )

        elif (
            user.account_status
            == User.AccountStatus.DEACTIVATED
        ):
            messages.error(
                request,
                "Your account has been deactivated.",
            )

        elif (
            user.account_status
            == User.AccountStatus.PENDING
        ):
            messages.warning(
                request,
                (
                    "Your account is waiting for "
                    "administrator approval."
                ),
            )

        elif (
            user.account_status
            == User.AccountStatus.LOCKED
        ):
            messages.error(
                request,
                (
                    "Your account is locked. "
                    "Please contact an administrator."
                ),
            )

        elif (
            user.account_status
            != User.AccountStatus.ACTIVE
        ):
            messages.error(
                request,
                "Your account is not available for login.",
            )

        else:
            # Re-check ACTIVE state atomically after authenticate(). If a
            # concurrent failed-login request locked the account after the
            # authentication query, the stale User object must not be allowed
            # to create a session.
            with transaction.atomic():
                login_claimed = (
                    _claim_successful_login_state(
                        user
                    )
                )

                if login_claimed:
                    login(
                        request,
                        user,
                    )

            if not login_claimed:
                if (
                    user.account_status
                    == User.AccountStatus.LOCKED
                ):
                    messages.error(
                        request,
                        (
                            "Your account became locked while the login "
                            "request was being processed. Please try again "
                            "after the lock period or contact an administrator."
                        ),
                    )
                else:
                    messages.error(
                        request,
                        (
                            "Your account state changed while the login "
                            "request was being processed. Please try again."
                        ),
                    )

                return render(
                    request,
                    "accounts/login.html",
                    {
                        "form": form,
                    },
                )

            messages.success(
                request,
                (
                    "Welcome, "
                    f"{user.full_name or user.username}."
                ),
            )

            return redirect(
                "accounts:dashboard_redirect"
            )

    return render(
        request,
        "accounts/login.html",
        {
            "form": form,
        },
    )


@login_required
@require_POST
def logout_view(request):
    """
    End the authenticated user's session.
    """

    logout(request)

    messages.success(
        request,
        "You have been logged out successfully.",
    )

    return redirect(
        "accounts:login"
    )


@login_required
def dashboard_redirect_view(request):
    """
    Redirect authenticated users to the Dashboard application.
    """

    return redirect(
        "dashboard:dashboard_redirect"
    )


@login_required
def profile_view(request):
    """
    Display only the logged-in user's profile.
    """

    return render(
        request,
        "accounts/profile.html",
        {
            "user_profile": request.user,
        },
    )


@login_required
def update_profile_view(request):
    """
    Allow the logged-in user to update their own profile.
    """

    if request.method == "POST":
        form = UserProfileForm(
            request.POST,
            request.FILES,
            instance=request.user,
        )

        if form.is_valid():
            form.save()

            messages.success(
                request,
                "Profile updated successfully.",
            )

            return redirect(
                "accounts:profile"
            )
    else:
        form = UserProfileForm(
            instance=request.user,
        )

    return render(
        request,
        "accounts/update_profile.html",
        {
            "form": form,
        },
    )
