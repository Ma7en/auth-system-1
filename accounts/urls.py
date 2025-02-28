from django.urls import path, include


#
from rest_framework_simplejwt.views import TokenRefreshView


#
from accounts import views


urlpatterns = [
    # =================================================================
    # *** User auths API Endpoints *** #
    # ================================================================
    # *** 1) Admin *** #
    # (Registration)
    path(
        "admin/register/",
        views.AdminRegisterView.as_view(),
        name="admin-register-api",
    ),
    # (ID)
    path(
        "admin/<int:pk>/",
        views.AdminIDView.as_view(),
        name="admin-user-id",
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
    # *** 2) Doctor *** #
    # (Registration)
    path(
        "doctor/register/",
        views.DoctorRegisterView.as_view(),
        name="doctor-register-api",
    ),
    # (ID)
    path(
        "doctor/<int:pk>/",
        views.DoctorIDView.as_view(),
        name="doctor-user-id",
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
    # ================================================================
    # *** 3) Staff *** #
    # (Registration)
    path(
        "staff/register/",
        views.StaffRegisterView.as_view(),
        name="staff-register-api",
    ),
    # (ID)
    path(
        "staff/<int:pk>/",
        views.StaffIDView.as_view(),
        name="staff-user-id",
    ),
    # (Profile)
    path(
        "staff/profile/<int:pk>/",
        views.StaffProfileView.as_view(),
        name="staff-profile-id",
    ),
    # (Resend OTP)
    path(
        "staff/resend-otp/",
        views.StaffResendOTPView.as_view(),
        name="staff-resend-otp-api",
    ),
    # (Verify Account)
    path(
        "staff/verify-account/",
        views.StaffVerifyAccountView.as_view(),
        name="verify-account-api",
    ),
    # (Login)
    path(
        "staff/login/",
        views.StaffLoginView.as_view(),
        name="staff-login-api",
    ),
    # (Refresh)
    path(
        "staff/refresh/",
        views.StaffRefreshView.as_view(),
        name="staff-user-refresh",
    ),
    # (Change Password)
    path(
        "staff/change-password/",
        views.StaffChangePasswordView.as_view(),
        name="staff-change-password-api",
    ),
    # (Logout)
    path(
        "staff/logout/",
        views.StaffLogoutView.as_view(),
        name="staff-logout-api",
    ),
    # (Reset Password)
    path(
        "staff/reset-password/",
        views.StaffPasswordResetView.as_view(),
        name="staff-reset-password-api",
    ),
    # (Confirm Reset Password)
    path(
        "staff/confirm-reset-password/",
        views.StaffConfirmResetPasswordView.as_view(),
        name="staff-confirm-reset-password",
    ),
    # ================================================================
    # *** 4) Patient *** #
    # (Registration)
    path(
        "patient/register/",
        views.PatientRegisterView.as_view(),
        name="patient-register-api",
    ),
    # (ID)
    path(
        "patient/<int:pk>/",
        views.PatientIDView.as_view(),
        name="patient-user-id",
    ),
    # (Profile)
    path(
        "patient/profile/<int:pk>/",
        views.PatientProfileView.as_view(),
        name="patient-profile-id",
    ),
    # (Resend OTP)
    path(
        "patient/resend-otp/",
        views.PatientResendOTPView.as_view(),
        name="patient-resend-otp-api",
    ),
    # (Verify Account)
    path(
        "patient/verify-account/",
        views.PatientVerifyAccountView.as_view(),
        name="verify-account-api",
    ),
    # (Login)
    path(
        "patient/login/",
        views.PatientLoginView.as_view(),
        name="patient-login-api",
    ),
    # (Refresh)
    path(
        "patient/refresh/",
        views.PatientRefreshView.as_view(),
        name="patient-user-refresh",
    ),
    # (Change Password)
    path(
        "patient/change-password/",
        views.PatientChangePasswordView.as_view(),
        name="patient-change-password-api",
    ),
    # (Logout)
    path(
        "patient/logout/",
        views.PatientLogoutView.as_view(),
        name="patient-logout-api",
    ),
    # (Reset Password)
    path(
        "patient/reset-password/",
        views.PatientPasswordResetView.as_view(),
        name="patient-reset-password-api",
    ),
    # (Confirm Reset Password)
    path(
        "patient/confirm-reset-password/",
        views.PatientConfirmResetPasswordView.as_view(),
        name="patient-confirm-reset-password",
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
