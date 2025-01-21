from django.urls import path, include


#
from rest_framework_simplejwt.views import TokenRefreshView


#
from accounts import views


urlpatterns = [
    # =================================================================
    # *** User auths API Endpoints *** #
    # ================================================================
    # *** Admin *** #
    # (Registration)
    path(
        "admin/register/",
        views.AdminRegisterView.as_view(),
        name="admin-register-api",
    ),
    # (Profile)
    path(
        "admin/profile/<int:pk>/",
        views.AdminProfileView.as_view(),
        name="admin-profile-id",
    ),
    # (Resend OTP)
    path(
        "admin/resend-otp/",
        views.AdminResendOTPView.as_view(),
        name="admin-resend-otp-api",
    ),
    # (Verify Account)
    path(
        "admin/verify-account/",
        views.AdminVerifyAccountView.as_view(),
        name="verify-account-api",
    ),
    # (Login)
    path(
        "admin/login/",
        views.AdminLoginView.as_view(),
        name="admin-login-api",
    ),
    # (ID)
    path(
        "admin/<int:pk>/",
        views.AdminIDView.as_view(),
        name="admin-user-id",
    ),
    # (Refresh)
    path(
        "admin/refresh/",
        views.AdminRefreshView.as_view(),
        name="admin-user-refresh",
    ),
    # (Change Password)
    path(
        "admin/change-password/",
        views.AdminChangePasswordView.as_view(),
        name="admin-change-password-api",
    ),
    # (Logout)
    path(
        "admin/logout/",
        views.AdminLogoutView.as_view(),
        name="admin-logout-api",
    ),
    # (Reset Password)
    path(
        "admin/reset-password/",
        views.AdminPasswordResetView.as_view(),
        name="admin-reset-password-api",
    ),
    # (Confirm Reset Password)
    path(
        "admin/confirm-reset-password/",
        views.AdminConfirmResetPasswordView.as_view(),
        name="admin-confirm-reset-password",
    ),
    # ================================================================
    # *** Doctor *** #
    # (Registration)
    path(
        "doctor/register/",
        views.DoctorRegisterView.as_view(),
        name="doctor-register-api",
    ),
    # (Profile)
    path(
        "doctor/profile/<int:pk>/",
        views.DoctorProfileView.as_view(),
        name="doctor-profile-id",
    ),
    # (Resend OTP)
    path(
        "doctor/resend-otp/",
        views.DoctorResendOTPView.as_view(),
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
    # (ID)
    path(
        "doctor/<int:pk>/",
        views.DoctorIDView.as_view(),
        name="doctor-user-id",
    ),
    # (Refresh)
    path(
        "doctor/refresh/",
        views.DoctorRefreshView.as_view(),
        name="doctor-user-refresh",
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
        views.DoctorConfirmResetPasswordView.as_view(),
        name="doctor-confirm-reset-password",
    ),
    # =================================================================
    # (Token Refreshing)
    path(
        "token/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    # =================================================================
]
