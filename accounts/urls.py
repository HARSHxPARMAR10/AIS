from django.urls import path

from . import views


app_name = "accounts"


urlpatterns = [
    path(
        "register/",
        views.register_view,
        name="register",
    ),

    path(
        "login/",
        views.login_view,
        name="login",
    ),

    path(
        "logout/",
        views.logout_view,
        name="logout",
    ),

    # Password-reset request form. Django sends a one-time reset link to the
    # active user's registered email address without revealing whether the
    # submitted address exists.
    path(
        "forgot-password/",
        views.AIDEXPasswordResetView.as_view(),
        name="password_reset",
    ),

    path(
        "forgot-password/sent/",
        views.AIDEXPasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),

    path(
        "reset-password/<uidb64>/<token>/",
        views.AIDEXPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),

    path(
        "reset-password/complete/",
        views.AIDEXPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),

    path(
        "dashboard/",
        views.dashboard_redirect_view,
        name="dashboard_redirect",
    ),

    path(
        "profile/",
        views.profile_view,
        name="profile",
    ),

    path(
        "profile/update/",
        views.update_profile_view,
        name="update_profile",
    ),
]
