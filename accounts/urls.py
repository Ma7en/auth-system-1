from django.urls import path, include


#
from rest_framework_simplejwt.views import TokenRefreshView


#
from accounts import views


urlpatterns = [
    # =================================================================
    # *** User auths API Endpoints *** #
    # ================================================================
    # *** Doctor *** #
    # (Registration)
    path(
        "doctor/register/",
        views.DoctorRegisterView.as_view(),
        name="doctor-register-api",
    ),
    #
    path(
        "doctor/resend-otp/",
        views.DriverResendOTPView.as_view(),
        name="doctor-resend-otp-api",
    ),
    # (Verify Account)
    path(
        "doctor/verify-account/",
        views.DoctorVerifyAccountView.as_view(),
        name="verify-account-api",
    ),
    # (Login)
    path(
        "doctor/login/",
        views.DoctorLoginView.as_view(),
        name="doctor-login-api",
    ),
    # (Change Password)
    path(
        "doctor/change-password/",
        views.DoctorChangePasswordView.as_view(),
        name="doctor-change-password-api",
    ),
    # (Logout)
    path(
        "doctor/logout/",
        views.DoctorLogoutView.as_view(),
        name="doctor-logout-api",
    ),
    # (Reset Password)
    path(
        "doctor/reset-password/",
        views.DoctorPasswordResetView.as_view(),
        name="doctor-reset-password-api",
    ),
    # (Confirm Reset Password)
    path(
        "doctor/confirm-reset-password/",
        views.DriverConfirmResetPasswordView.as_view(),
        name="doctor-confirm-reset-password",
    ),
    # (Token Refreshing)
    path(
        "token/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    # =================================================================
]
