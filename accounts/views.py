#
import jwt


#
from django.shortcuts import render
from smtplib import SMTPRecipientsRefused
from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.utils.translation import gettext_lazy as _


SECRET_KEY = settings.SECRET_KEY


#
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken


#
from accounts import models
from accounts import serializers
from accounts import utils


# *****************************************************************
# =================================================================
# *** Doctor (Register) *** #
class DoctorRegisterView(generics.CreateAPIView):
    queryset = models.User.objects.all()
    serializer_class = serializers.DoctorRegisterSerializer
    permission_classes = (AllowAny,)

    # 2
    def post(self, request):
        # logger.info(f"Received request data: {request.data}")
        serializer = serializers.DoctorRegisterSerializer(data=request.data)

        if serializer.is_valid():
            # Step 1: Save the user data using the serializer's create method
            # logger.info(f"Doctor created: {doctor.email}")
            doctor = serializer.save()
            doctor_data = serializers.UserSerializer(doctor).data

            # Step 2: Send OTP to the doctor's email using the utility function
            try:
                # Call the email-sending function
                utils.send_otp_for_doctor(doctor.email)
            except SMTPRecipientsRefused as e:
                # Handle invalid email error
                # error_messages = str(e.recipients)
                # print(f"Error sending OTP to {doctor.email}: {error_messages}")
                raise ValidationError(
                    {
                        "Error": "Invald Email",
                    }
                )

            # Step 3: Return success response
            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Doctor registered successfully, and We have sent an OTP to your Email!",
                "status_code": status_code,
                "data": doctor_data,
            }
            return Response(
                response,
                status=status.HTTP_201_CREATED,
            )

        # first_error_list = next(iter(serializer.errors.values()), [])
        # first_error_message = (
        #     first_error_list[0] if first_error_list else "Unknown error"
        # )
        status_code = status.HTTP_400_BAD_REQUEST
        response = {
            "success": "False",
            "code": 1,
            "message": serializer.errors,
            "status_code": status_code,
            "data": "",
        }
        return Response(
            response,  # Single error message
            status=status_code,
        )

    # 1
    # def post(self, request):
    #     serializer = self.serializer_class(data=request.data)

    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #     # print("\n\n\n\n\n\n\n\n\n")
    #     # print("user", serializer.data) # user {'first_name': 'mazen', 'last_name': 'saad', 'email': 'd34@gmail.com'}
    #     # print("\n\n\n\n\n\n\n\n\n")

    #     status_code = status.HTTP_200_OK
    #     response = {
    #         "success": "True",
    #         "code": 0,
    #         "message": "Doctor registered  successfully",
    #         "status_code": status_code,
    #         # "data": serializer,
    #     }
    #     return Response(
    #         response,
    #         status=status_code,
    #     )


# *** Doctor (Profile) *** #
class DoctorProfileView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.DoctorProfileSerializer
    # lookup_field = "passenger__id"  # This allows filtering by passenger ID

    def get_queryset(self):
        return models.DoctorProfile.objects.all()

    def get_object(self):
        try:
            doctor_pk = self.kwargs["pk"]  # 1
            doctor_profile = models.DoctorProfile.objects.get(user=doctor_pk)
            return doctor_profile
        except models.DoctorProfile.DoesNotExist:
            status_code = status.HTTP_404_NOT_FOUND
            raise NotFound(
                {
                    "success": "False",
                    "code": 1,
                    "message": "Doctor Profile not found",
                    "status_code": status_code,
                    "data": "",
                }
            )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        doctor_data = serializer.data

        status_code = status.HTTP_200_OK
        response = {
            "success": "True",
            "code": 0,
            "message": "Doctor Profile retrieved successfully",
            "status_code": status_code,
            "data": doctor_data,
        }
        return Response(
            response,
            status=status_code,
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        doctor_data = serializer.data
        status_code = status.HTTP_200_OK
        response = {
            "success": "True",
            "code": 0,
            "message": "Doctor Profile updated successfully",
            "status_code": status_code,
            "data": doctor_data,
        }
        return Response(
            response,
            status=status_code,
        )


# *** Doctor (Resend OTP) *** #
class DriverResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = serializers.DoctorResendOTPSerializer(data=request.data)

        if not serializer.is_valid():
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": serializer.errors,
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        email = serializer.validated_data["email"]
        try:
            user = models.User.objects.get(email=email)

            # Check if the driver is already verified
            if user.is_verified:
                status_code = status.HTTP_403_FORBIDDEN
                response = {
                    "success": "False",
                    "code": 1,
                    "message": "Your account has already been verified. Please go to the login page.",
                    "status_code": status_code,
                    "data": "",
                }
                return Response(
                    response,
                    status=status_code,
                )
            # Resend OTP if not verified
            utils.send_otp_for_doctor(user.email)
        except models.User.DoesNotExist:
            status_code = status.HTTP_404_NOT_FOUND
            response = {
                "success": "False",
                "code": 1,
                "message": "No user found with this email.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        status_code = status.HTTP_200_OK
        response = {
            "success": "True",
            "code": 0,
            "message": "OTP has been resent to your email.",
            "status_code": status_code,
            "data": "",
        }
        return Response(
            response,
            status=status_code,
        )


# *** Doctor (Verify Account) *** #
class DoctorVerifyAccountView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp_code = request.data.get("otp_code")

        # Ensure OTP code is provided
        if not otp_code:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "OTP code is required",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        try:
            # Retrieve the OTP record from OneTimeOTP model
            otp = models.OneTimeOTP.objects.get(otp=otp_code)
        except models.OneTimeOTP.DoesNotExist:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "Invalid OTP Code",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        # Check OTP expiration
        if otp.is_expired():
            # otp.delete()
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "OTP has expired",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        # Determine if the OTP belongs to a User
        if otp.user:
            user = otp.user
        else:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "No associated user for this OTP code",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        # Check if the user is already verified
        if user.is_verified:
            status_code = status.HTTP_200_OK
            response = {
                "success": "False",
                "code": 1,
                "message": "Email already verified",
                "status_code": status_code,
                "data": user,
            }
            return Response(
                response,
                status=status_code,
            )

        # Mark user as verified
        user.is_verified = True
        user.save()

        # Send verification success email
        utils.send_verification_email(
            user, otp_code
        )  # Assuming this sends the confirmation email

        # Optionally delete OTP record after successful verification
        otp.delete()

        # print("\n\n\n\n\n\n")
        # print("user", user)
        # print("\n\n\n\n\n\n")
        doctor_data = serializers.UserSerializer(user).data

        status_code = status.HTTP_200_OK
        response = {
            "success": "False",
            "code": 1,
            "message": "Email verified successfully",
            "status_code": status_code,
            "data": doctor_data,
        }
        return Response(
            response,
            status=status_code,
        )


# *** Doctor (Login) *** #
# 2
class DoctorLoginView(APIView):
    def post(self, request):
        # Deserialize the driver login data
        serializer = serializers.DoctorLoginSerializer(data=request.data)

        if serializer.is_valid():
            doctor = serializer.validated_data  # Extract the validated doctor

            if not doctor.is_verified:
                status_code = status.HTTP_403_FORBIDDEN
                response = {
                    "success": "False",
                    "code": 1,
                    "message": "Your account is not verified. Please verify your account to proceed.",
                    "status_code": status_code,
                    "data": "",
                }
                return Response(
                    response,
                    status=status_code,
                )

            # Generate refresh token and include doctor_id in the token payload
            refresh = RefreshToken.for_user(doctor)
            refresh["doctor_id"] = (
                doctor.id
            )  # Explicitly add driver_id to the token payload

            # Generate access token
            access_token = refresh.access_token

            # Return tokens
            # print("\n\n\n\n\n")
            # print("doctor_data", doctor_data)
            # print("\n\n\n\n\n")
            doctor_data = serializers.UserSerializer(doctor).data
            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Invalid OTP Code",
                "status_code": status_code,
                "data": doctor_data,
                "access_token": str(access_token),
                "refresh_token": str(refresh),
            }
            return Response(
                response,
                status=status_code,
            )

        status_code = status.HTTP_400_BAD_REQUEST
        response = {
            "success": "False",
            "code": 1,
            "message": serializer.errors,
            "status_code": status_code,
            "data": "",
        }
        return Response(
            response,  # Single error message
            status=status_code,
        )


# 1
# *** Doctor (Login) *** #
# class DoctorLoginView(RetrieveAPIView):
#     permission_classes = (AllowAny,)
#     serializer_class = serializers.DoctorLoginSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         status_code = status.HTTP_200_OK
#         response = {
#             "success": "True",
#             "code": 0,
#             "status_code": status_code,
#             "message": "User logged in Successfully",
#             "data": serializer,
#             "token": serializer.data["token"],
#         }
#         return Response(
#             response,
#             status=status_code,
#         )


# *** Doctor (ID) *** #
class DoctorIDView(APIView):
    def get(self, request, pk):
        try:
            # البحث عن السائق باستخدام المعرف (pk)
            doctor = models.User.objects.get(pk=pk)
        except models.User.DoesNotExist:
            # raise NotFound(
            #     {
            #         "message": "Doctor not found.",
            #     }
            # )
            status_code = status.HTTP_404_NOT_FOUND
            response = {
                "success": "False",
                "code": 1,
                "message": "Doctor not found.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        # تحويل الكائن إلى JSON باستخدام Serializer
        doctor_data = serializers.UserSerializer(doctor).data

        status_code = status.HTTP_200_OK
        response = {
            "success": "True",
            "code": 0,
            "message": "Doctor retrieved successfully.",
            "status_code": status_code,
            "data": doctor_data,
        }
        return Response(
            response,
            status=status_code,
        )


# *** Doctor (Refresh) *** #
class DoctorRefreshView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                # raise ValidationError(
                #     {
                #         "refresh_token": "This field is required.",
                #     }
                # )
                status_code = status.HTTP_404_NOT_FOUND
                response = {
                    "success": "False",
                    "code": 1,
                    "message": {
                        "refresh_token": "This field is required.",
                    },
                    "status_code": status_code,
                    "data": "",
                }
                return Response(
                    response,
                    status=status_code,
                )

            # Decode the JWT token
            payload = jwt.decode(
                refresh_token, SECRET_KEY, algorithms=["HS256"]
            )  # {'token_type': 'refresh', 'exp': 1737402322, 'iat': 1737315922, 'jti': '626f3935d64e4ebcbfcb53d54041f2ab', 'user_id': 1, 'doctor_id': 1}

            # Retrieve user_id from the token payload
            user_id = payload.get("user_id")
            if not user_id:
                raise ValidationError(
                    {
                        "refresh_token": "Invalid token payload.",
                    }
                )

            # Fetch the Driver object
            doctor = models.User.objects.get(id=user_id)

            # Serialize the Driver object
            doctor_data = serializers.UserSerializer(doctor).data

            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Doctor retrieved successfully.",
                "status_code": status_code,
                "data": doctor_data,
            }
            return Response(
                response,
                status=status_code,
            )

        except models.User.DoesNotExist:
            raise ValidationError(
                {
                    "message": "Driver not found.",
                }
            )

        except jwt.ExpiredSignatureError:
            raise ValidationError(
                {
                    "message": "Refresh token has expired.",
                }
            )

        except jwt.InvalidTokenError:
            raise ValidationError(
                {
                    "message": "Invalid refresh token.",
                }
            )

        except Exception as e:
            raise ValidationError(
                {
                    "message": str(e),
                }
            )


# *** Doctor (Change Password) *** #
class DoctorChangePasswordView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")

            if not refresh_token:
                raise ValidationError({"refresh_token": "This field is required."})

            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
            doctor_id = payload.get("doctor_id")

            # Fetch the doctor
            doctor = models.User.objects.get(id=doctor_id)

            # Validate old password
            old_password = request.data.get("old_password")

            if not old_password or not check_password(old_password, doctor.password):
                raise ValidationError({"message": "Old password is incorrect."})

            # Validate new passwords
            new_password = request.data.get("new_password")
            confirm_password = request.data.get("confirm_password")
            # validate_password(new_password, confirm_password)
            # Change password
            doctor.set_password(new_password)
            doctor.save()
            utils.send_change_password_confirm(doctor)

            doctor_data = serializers.UserSerializer(doctor).data
            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Password changed successfully.",
                "status_code": status_code,
                "data": doctor_data,
            }
            return Response(
                response,
                status=status_code,
            )

        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValidationError("Invalid token")
        except models.User.DoesNotExist:
            raise ValidationError("Driver not found")
        except ValidationError as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": e.detail,
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )


# *** Doctor (Logout) *** #
class DoctorLogoutView(APIView):
    def post(self, request):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                status_code = status.HTTP_400_BAD_REQUEST
                response = {
                    "success": "False",
                    "code": 1,
                    "message": "Refresh token not provided.",
                    "status_code": status_code,
                    "data": "",
                }
                return Response(
                    response,
                    status=status_code,
                )

            # Decode the refresh token
            token = RefreshToken(refresh_token)
            doctor_id_in_token = token.payload.get("user_id")

            if not doctor_id_in_token:
                status_code = status.HTTP_403_FORBIDDEN
                response = {
                    "success": "False",
                    "code": 1,
                    "message": "Invalid token: user_id missing.",
                    "status_code": status_code,
                    "data": "",
                }
                return Response(
                    response,
                    status=status_code,
                )

            # Validate that the doctor exists and matches the current authenticated doctor
            doctor = models.User.objects.filter(id=doctor_id_in_token).first()
            if not doctor:
                status_code = status.HTTP_403_FORBIDDEN
                response = {
                    "success": "False",
                    "code": 1,
                    "message": "Invalid token: Doctor not found.",
                    "status_code": status_code,
                    "data": "",
                }
                return Response(
                    response,
                    status=status_code,
                )

            # Expire the token (logout the driver)
            token.set_exp()

            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Logout successful.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )
        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": str(e),
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )


# *** Doctor (Reset Password) *** #
class DoctorPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get("email")

        if not email:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "Email is required.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        try:
            doctor = models.User.objects.get(email=email)
            if not doctor.is_verified:
                status_code = status.HTTP_403_FORBIDDEN
                response = {
                    "success": "False",
                    "code": 1,
                    "message": "Your account is not verified. Please verify your account to proceed.",
                    "status_code": status_code,
                    "data": "",
                }
                return Response(
                    response,
                    status=status_code,
                )

        except models.User.DoesNotExist:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "Doctor with this email does not exist.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        # Send OTP for password reset
        try:
            utils.send_otp_for_password_reset(email, user_type="doctor")
            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "OTP has been sent to your email.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )
        except ValueError as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": str(e),
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )


# 1
# *** Doctor (Confirm Reset Password) *** #
# class DriverConfirmResetPasswordView(APIView):
#     """
#     This view allows a driver to reset their password after OTP verification.
#     """

#     def post(self, request):
#         serializer = serializers.DoctorConfirmResetPasswordSerializer(data=request.data)
#         print("\n\n\n\n\n\n")
#         print("serializer", serializer)
#         print("\n\n\n\n\n\n")

#         if serializer.is_valid():
#             serializer.save()
#             status_code = status.HTTP_200_OK
#             response = {
#                 "success": "True",
#                 "code": 0,
#                 "message": "Password has been reset successfully.",
#                 "status_code": status_code,
#                 "data": serializer,
#             }
#             return Response(
#                 response,
#                 status=status_code,
#             )

#         status_code = status.HTTP_400_BAD_REQUEST
#         response = {
#             "success": "False",
#             "code": 1,
#             "message": serializer.errors,
#             "status_code": status_code,
#             "data": "",
#         }
#         return Response(
#             response,  # Single error message
#             status=status_code,
#         )


# 2
# *** Doctor (Confirm Reset Password) *** #
class DriverConfirmResetPasswordView(APIView):
    """
    This view allows a driver to reset their password after OTP verification.
    """

    def post(self, request):
        otp = request.data.get("otp")
        password = request.data.get("password")
        password2 = request.data.get("password2")

        if password != password2:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "Passwords do not match.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        # Validate OTP
        try:
            otp_instance = models.OneTimeOTP.objects.get(otp=otp, user__isnull=False)
        except models.OneTimeOTP.DoesNotExist:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "Invalid OTP.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        if otp_instance.is_expired():
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                "success": "False",
                "code": 1,
                "message": "OTP has expired.",
                "status_code": status_code,
                "data": "",
            }
            return Response(
                response,
                status=status_code,
            )

        doctor = otp_instance.user
        password = password

        doctor.set_password(password)
        doctor.save()
        utils.send_reset_password_confirm(doctor)

        # Delete the used OTP
        models.OneTimeOTP.objects.filter(user=doctor).delete()

        doctor_data = serializers.UserSerializer(doctor).data
        status_code = status.HTTP_200_OK
        response = {
            "success": "True",
            "code": 0,
            "message": "Confirm Reset Password Successfully.",
            "status_code": status_code,
            "data": doctor_data,
        }
        return Response(
            response,
            status=status_code,
        )


# *****************************************************************
# =================================================================
# ***   *** #
