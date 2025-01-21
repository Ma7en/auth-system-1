import random
import logging


#
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.timezone import now
from django.conf import settings
from django.utils.translation import gettext_lazy as _


#
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status


#
from accounts import models

logger = logging.getLogger(__name__)


# *****************************************************************
# ================================================================
current_year = now().year


# *****************************************************************
# ================================================================
# *** Generate OTP *** #
def generate_otp():
    return str(random.randint(100000, 999999))  # Generates a 6-digit OTP


# *****************************************************************
# ================================================================
# *** Send OTP For Doctor ***#
def send_otp_for_doctor(email):
    try:
        doctor = models.User.objects.get(email=email)
        otp = generate_otp()

        # Create OTP record for the driver
        otp_record = models.OneTimeOTP.objects.create(user=doctor, otp=otp)

        # Send OTP to driver's email
        context = {
            "name": doctor.first_name,
            "OTP": otp,
            "current_year": current_year,
        }
        subject = "Doctor Confirmation Email"
        template = "send_otp.html"
        html_content = render_to_string(template, context)
        plain_message = strip_tags(html_content)

        send_mail(
            subject,
            plain_message,
            settings.EMAIL_HOST_USER,
            [doctor.email],
            html_message=html_content,
            fail_silently=False,
        )

        logger.info(f"OTP sent to driver {doctor.email}. OTP: {otp}")

    except models.User.DoesNotExist:
        logger.error(f"Driver with email {email} not found.")
        raise ValueError(_(f"Driver with email {email} does not exist"))
    except Exception as e:
        logger.error(f"Error sending OTP to driver {email}: {str(e)}")
        raise ValueError(_(f"Error sending OTP to driver {email}: {str(e)}"))


# *****************************************************************
# ================================================================
# *** Send Verification Email ***#
def send_verification_email(user, otp):
    subject = "Email Verification - Your Account Is Confirmed"
    plain_message = f"Dear {user.first_name},\n\nPlease use the following OTP to verify your email: {otp}\n\nThank you!"
    receiver_email = user.email

    # Render the HTML content
    html_message = render_to_string(
        "email_confirmation.html",
        {
            "name": user.first_name,
            "OTP": otp,
            "current_year": current_year,
        },
    )

    # Send email
    send_mail(
        subject,
        plain_message,  # Fallback plain-text message
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[receiver_email],
        html_message=html_message,
        fail_silently=False,  # Fail loudly in development
    )


# *****************************************************************
# # ================================================================
# *** Send OTP For Password Reset ***#
def send_otp_for_password_reset(email, user_type):
    otp = generate_otp()

    if user_type == "doctor":
        try:
            user = models.User.objects.get(email=email)
        except models.User.DoesNotExist:
            raise ValueError(f"Doctor with email {email} not found")
    elif user_type == "passenger":
        try:
            user = models.User.objects.get(email=email)
        except models.User.DoesNotExist:
            raise ValueError(f"Passenger with email {email} not found")

    # Create OTP record
    otp_record = models.OneTimeOTP.objects.create(otp=otp, user=user)

    # Send OTP to the user's email
    context = {
        "name": user.first_name,
        "OTP": otp,
        "current_year": current_year,
    }
    subject = f"{user_type.capitalize()} Password Reset OTP"
    template = "reset_otp_email.html"  # Your email template for OTP
    html_content = render_to_string(template, context)
    plain_message = strip_tags(html_content)
    receiver_email = user.email

    send_mail(
        subject,
        plain_message,
        settings.EMAIL_HOST_USER,
        recipient_list=[receiver_email],
        html_message=html_content,
        fail_silently=False,
    )

    # return otp_record  # Optionally return OTP for debugging/logging purposes


# ******************************************************************
# # ================================================================
# *** Send Reset Password Confirm *** #
def send_reset_password_confirm(user):
    subject = "Reset Password Confirmation"
    plain_message = (
        f"Dear {user.first_name}, your password has been successfully reseted "
    )
    receiver_email = user.email

    # Render the HTML content
    html_message = render_to_string(
        "password_reset_confirm.html",
        {
            "name": user.first_name,
            "current_year": current_year,
        },
    )

    # Send email
    send_mail(
        subject,
        plain_message,  # Fallback plain-text message
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[receiver_email],
        html_message=html_message,
        fail_silently=False,  # Fail loudly in development
    )


# ****************************************************************
# ================================================================
# *** Send Change Password Confirm ***#
def send_change_password_confirm(user):
    subject = "Change Password Confirmation"
    plain_message = (
        f"Dear {user.first_name}, your password has been successfully changed"
    )
    receiver_email = user.email

    # Render the HTML content
    html_message = render_to_string(
        "password_change_confirm.html",
        {
            "name": user.first_name,
            "current_year": current_year,
        },
    )

    # Send email
    send_mail(
        subject,
        plain_message,  # Fallback plain-text message
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[receiver_email],
        html_message=html_message,
        fail_silently=False,  # Fail loudly in development
    )


# ****************************************************************
# ================================================================
# *** Return Response ***#
def FunReturn(code, message, status, data=""):
    if code == 0:
        success = "True"
    elif code == 1:
        success = "False"

    response = {
        "success": success,
        "code": code,
        "message": message,
        "status_code": status,
        "data": data,
    }
    return Response(
        response,
        status=status,
    )


# ****************************************************************
# ================================================================
# ***  ***#


# ****************************************************************
# ================================================================

"""
def verify_otp(otp_code):

        #otp_code = request.data.get('otp_code')

        # Ensure OTP code is provided
        if not otp_code:
            return Response({
                'message': 'OTP code is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the OTP record from OneTimePassword model
            otp = OneTimePassword.objects.get(otp=otp_code)
        except OneTimePassword.DoesNotExist:
            return Response({
                'message': 'Invalid OTP code'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check OTP expiration
        if otp.is_expired():
            #otp.delete()
            return Response({
                'message': 'OTP has expired'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Determine if the OTP belongs to a Driver or Passenger
        if otp.driver:
            user = otp.driver
        elif otp.passenger:
            user = otp.passenger
        else:
            return Response({
                'message': 'No associated user for this OTP code'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if the user is already verified
        if user.is_verified:
            return Response({
                'message': 'Email already verified',
                'data': {
                    'email': user.email,
                    'is_verified': user.is_verified
                }
            }, status=status.HTTP_200_OK)

        # Mark user as verified
        user.is_verified = True
        user.save()

"""
