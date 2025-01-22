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
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken


#
from accounts import models
from accounts import serializers
from accounts import utils


# *****************************************************************
# =================================================================
# *** 1) Admin (Register) *** #
class AdminRegisterView(generics.CreateAPIView):
    queryset = models.User.objects.all()
    serializer_class = serializers.AdminRegisterSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = serializers.AdminRegisterSerializer(data=request.data)

        if serializer.is_valid():
            # Step 1: Save the user data using the serializer's create method
            admin = serializer.save()
            admin_data = serializers.UserSerializer(admin).data

            # Step 2: Send OTP to the admin's email using the utility function
            try:
                # Call the email-sending function
                utils.send_otp_for_user(admin.email, "admin")
            except SMTPRecipientsRefused as e:
                raise ValidationError(
                    {
                        "Error": f"Error sending OTP to {admin.email}: {e}",
                    }
                )

            # Step 3: Return success response
            message = (
                "Admin registered successfully, and We have sent an OTP to your Email!"
            )
            return utils.FunReturn(
                0,
                message,
                status.HTTP_201_CREATED,
                admin_data,
            )

        # Step 4:
        message = serializer.errors
        return utils.FunReturn(
            1,
            message,
            status.HTTP_400_BAD_REQUEST,
        )


# *** Admin (Profile) *** #
class AdminProfileView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.AdminProfileSerializer

    def get_queryset(self):
        return models.AdminProfile.objects.all()

    def get_object(self):
        try:
            admin_pk = self.kwargs["pk"]  # 1
            admin_profile = models.AdminProfile.objects.get(user=admin_pk)
            return admin_profile
        except models.AdminProfile.DoesNotExist:
            status_code = status.HTTP_404_NOT_FOUND
            raise NotFound(
                {
                    "success": "False",
                    "code": 1,
                    "message": "Admin Profile not found",
                    "status_code": status_code,
                    "data": "",
                }
            )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        admin_data = serializer.data

        if admin_data["admin"]["is_admin"] == False:
            message = "Admin Profile whit this id is not Found"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Admin Profile retrieved successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            admin_data,
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        admin_data = serializer.data
        message = "Admin Profile updated successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            admin_data,
        )


# *** Admin (Resend OTP) *** #
class AdminResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = serializers.AdminResendOTPSerializer(data=request.data)

        if not serializer.is_valid():
            message = serializer.errors
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data["email"]
        try:
            user = models.User.objects.get(email=email)

            # Check if the doctor is already verified
            if user.is_verified:
                message = "Your account has already been verified. Please go to the login page."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Resend OTP if not verified
            utils.send_otp_for_user(user.email, "admin")
        except models.User.DoesNotExist:
            message = "No user found with this email."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "OTP has been resent to your email."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
        )


# *** Admin (Verify Account) *** #
class AdminVerifyAccountView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp_code = request.data.get("otp_code")

        # Ensure OTP code is provided
        if not otp_code:
            message = "OTP code is required"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Retrieve the OTP record from OneTimeOTP model
            otp = models.OneTimeOTP.objects.get(otp=otp_code)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP Code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check OTP expiration
        if otp.is_expired():
            message = "OTP has expired"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Determine if the OTP belongs to a User
        if otp.user:
            user = otp.user
        else:
            message = "No associated user for this OTP code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check if the user is already verified
        if user.is_verified:
            message = "Email already verified"
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
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

        doctor_data = serializers.UserSerializer(user).data
        message = "Email verified successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            doctor_data,
        )


# *** Admin (Login) *** #
class AdminLoginView(APIView):
    def post(self, request):
        # Deserialize the admin login data
        serializer = serializers.AdminLoginSerializer(data=request.data)

        if serializer.is_valid():
            admin = serializer.validated_data  # Extract the validated admin

            if not admin.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Generate refresh token and include admin_id in the token payload
            refresh = RefreshToken.for_user(admin)
            refresh["admin_id"] = (
                admin.id
            )  # Explicitly add admin_id to the token payload

            # Generate access token
            access_token = refresh.access_token

            admin_data = serializers.UserSerializer(admin).data

            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Login successfully.",
                "status_code": status_code,
                "data": admin_data,
                "access_token": str(access_token),
                "refresh_token": str(refresh),
            }
            return Response(
                response,
                status=status_code,
            )

        message = serializer.errors
        return utils.FunReturn(
            1,
            message,
            status.HTTP_400_BAD_REQUEST,
        )


# *** Admin (ID) *** #
class AdminIDView(APIView):
    def get(self, request, pk):
        try:
            admin = models.User.objects.get(pk=pk)
        except models.User.DoesNotExist:
            message = "Admin not found."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        admin_data = serializers.UserSerializer(admin).data

        if admin_data["is_admin"] == False:
            message = "Admin whit this id is not Found"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Admin retrieved successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            admin_data,
        )


# *** Admin (Refresh) *** #
class AdminRefreshView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = {
                    "refresh_token": "This field is required.",
                }
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_400_BAD_REQUEST,
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

            # Fetch the Admin object
            admin = models.User.objects.get(id=user_id)

            # Serialize the Admin object
            admin_data = serializers.UserSerializer(admin).data
            message = "Admin retrieved successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                admin_data,
            )

        except models.User.DoesNotExist:
            raise ValidationError(
                {
                    "message": "Admin not found.",
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


# *** Admin (Change Password) *** #
class AdminChangePasswordView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")

            if not refresh_token:
                raise ValidationError({"refresh_token": "This field is required."})

            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
            admin_id = payload.get("admin_id")

            # Fetch the admin
            admin = models.User.objects.get(id=admin_id)

            # Validate old password
            old_password = request.data.get("old_password")

            if not old_password or not check_password(old_password, admin.password):
                raise ValidationError({"message": "Old password is incorrect."})

            # Validate new passwords
            new_password = request.data.get("new_password")
            confirm_password = request.data.get("confirm_password")

            # validate_password(new_password, confirm_password)

            # Change password
            admin.set_password(new_password)
            admin.save()
            utils.send_change_password_confirm(admin)

            admin_data = serializers.UserSerializer(admin).data
            message = "Password changed successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                admin_data,
            )

        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValidationError("Invalid token")
        except models.User.DoesNotExist:
            raise ValidationError("Admin not found")
        except ValidationError as e:
            message = e.detail
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Admin (Logout) *** #
class AdminLogoutView(APIView):
    def post(self, request):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = "Refresh token not provided."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_400_BAD_REQUEST,
                )

            # Decode the refresh token
            token = RefreshToken(refresh_token)
            admin_id_in_token = token.payload.get("user_id")

            if not admin_id_in_token:
                message = "Invalid token: user_id missing."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Validate that the admin exists and matches the current authenticated admin
            admin = models.User.objects.filter(id=admin_id_in_token).first()
            if not admin:
                message = "Invalid token: admin not found."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Expire the token (logout the admin)
            token.set_exp()

            message = "Logout successful."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except Exception as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Admin (Reset Password) *** #
class AdminPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get("email")

        if not email:
            message = "Email is required."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            admin = models.User.objects.get(email=email)
            if not admin.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

        except models.User.DoesNotExist:
            message = "Admin with this email does not exist."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Send OTP for password reset
        try:
            utils.send_otp_for_password_reset(email, user_type="admin")
            message = "OTP has been sent to your email."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except ValueError as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Admin (Confirm Reset Password) *** #
class AdminConfirmResetPasswordView(APIView):
    """
    This view allows a Admin to reset their password after OTP verification.
    """

    def post(self, request):
        otp = request.data.get("otp")
        password = request.data.get("password")
        password2 = request.data.get("password2")

        if password != password2:
            message = "Passwords do not match."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Validate OTP
        try:
            otp_instance = models.OneTimeOTP.objects.get(otp=otp, user__isnull=False)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        if otp_instance.is_expired():
            message = "OTP has expired."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        admin = otp_instance.user
        password = password

        admin.set_password(password)
        admin.save()
        utils.send_reset_password_confirm(admin)

        # Delete the used OTP
        models.OneTimeOTP.objects.filter(user=admin).delete()

        admin_data = serializers.UserSerializer(admin).data

        message = "Confirm Reset Password Successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            admin_data,
        )


# *****************************************************************
# =================================================================
# *** 2) Doctor (Register) *** #
class DoctorRegisterView(generics.CreateAPIView):
    queryset = models.User.objects.all()
    serializer_class = serializers.DoctorRegisterSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = serializers.DoctorRegisterSerializer(data=request.data)

        if serializer.is_valid():
            # Step 1: Save the user data using the serializer's create method
            doctor = serializer.save()
            doctor_data = serializers.UserSerializer(doctor).data

            # Step 2: Send OTP to the doctor's email using the utility function
            try:
                # Call the email-sending function
                utils.send_otp_for_user(doctor.email, "doctor")
            except SMTPRecipientsRefused as e:
                raise ValidationError(
                    {
                        "Error": f"Error sending OTP to {doctor.email}: {e}",
                    }
                )

            # Step 3: Return success response
            message = (
                "Doctor registered successfully, and We have sent an OTP to your Email!"
            )
            return utils.FunReturn(
                0,
                message,
                status.HTTP_201_CREATED,
                doctor_data,
            )

        message = serializer.errors
        return utils.FunReturn(
            1,
            message,
            status.HTTP_400_BAD_REQUEST,
        )


# *** Doctor (Profile) *** #
class DoctorProfileView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.DoctorProfileSerializer

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

        if doctor_data["doctor"]["is_doctor"] == False:
            message = "Doctor Profile whit this id is not Found"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Doctor Profile retrieved successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            doctor_data,
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        doctor_data = serializer.data
        message = "Doctor Profile updated successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            doctor_data,
        )


# *** Doctor (Resend OTP) *** #
class DoctorResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = serializers.DoctorResendOTPSerializer(data=request.data)

        if not serializer.is_valid():
            message = serializer.errors
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data["email"]
        try:
            user = models.User.objects.get(email=email)

            # Check if the doctor is already verified
            if user.is_verified:
                message = "Your account has already been verified. Please go to the login page."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Resend OTP if not verified
            utils.send_otp_for_user(user.email, "doctor")
        except models.User.DoesNotExist:
            message = "No user found with this email."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "OTP has been resent to your email."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
        )


# *** Doctor (Verify Account) *** #
class DoctorVerifyAccountView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp_code = request.data.get("otp_code")

        # Ensure OTP code is provided
        if not otp_code:
            message = "OTP code is required"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Retrieve the OTP record from OneTimeOTP model
            otp = models.OneTimeOTP.objects.get(otp=otp_code)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP Code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check OTP expiration
        if otp.is_expired():
            message = "OTP has expired"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Determine if the OTP belongs to a User
        if otp.user:
            user = otp.user
        else:
            message = "No associated user for this OTP code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check if the user is already verified
        if user.is_verified:
            message = "Email already verified"
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
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

        doctor_data = serializers.UserSerializer(user).data
        message = "Email verified successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            doctor_data,
        )


# *** Doctor (Login) *** #
class DoctorLoginView(APIView):
    def post(self, request):
        # Deserialize the doctor login data
        serializer = serializers.DoctorLoginSerializer(data=request.data)

        if serializer.is_valid():
            doctor = serializer.validated_data  # Extract the validated doctor

            if not doctor.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Generate refresh token and include doctor_id in the token payload
            refresh = RefreshToken.for_user(doctor)
            refresh["doctor_id"] = (
                doctor.id
            )  # Explicitly add doctor_id to the token payload

            # Generate access token
            access_token = refresh.access_token

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

        message = serializer.errors
        return utils.FunReturn(
            1,
            message,
            status.HTTP_400_BAD_REQUEST,
        )


# *** Doctor (ID) *** #
class DoctorIDView(APIView):
    def get(self, request, pk):
        try:
            doctor = models.User.objects.get(pk=pk)
        except models.User.DoesNotExist:
            message = "Doctor not found."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        doctor_data = serializers.UserSerializer(doctor).data

        if doctor_data["is_doctor"] == False:
            message = "Doctor with this Id is not Found."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Doctor retrieved successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            doctor_data,
        )


# *** Doctor (Refresh) *** #
class DoctorRefreshView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = {
                    "refresh_token": "This field is required.",
                }
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_400_BAD_REQUEST,
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

            # Fetch the Doctor object
            doctor = models.User.objects.get(id=user_id)

            # Serialize the Doctor object
            doctor_data = serializers.UserSerializer(doctor).data
            message = "Doctor retrieved successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                doctor_data,
            )

        except models.User.DoesNotExist:
            raise ValidationError(
                {
                    "message": "Doctor not found.",
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
            message = "Password changed successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                doctor_data,
            )

        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValidationError("Invalid token")
        except models.User.DoesNotExist:
            raise ValidationError("Doctor not found")
        except ValidationError as e:
            message = e.detail
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Doctor (Logout) *** #
class DoctorLogoutView(APIView):
    def post(self, request):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = "Refresh token not provided."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_400_BAD_REQUEST,
                )

            # Decode the refresh token
            token = RefreshToken(refresh_token)
            doctor_id_in_token = token.payload.get("user_id")

            if not doctor_id_in_token:
                message = "Invalid token: user_id missing."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Validate that the doctor exists and matches the current authenticated doctor
            doctor = models.User.objects.filter(id=doctor_id_in_token).first()
            if not doctor:
                message = "Invalid token: Doctor not found."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Expire the token (logout the doctor)
            token.set_exp()
            message = "Logout successful."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except Exception as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Doctor (Reset Password) *** #
class DoctorPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get("email")

        if not email:
            message = "Email is required."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            doctor = models.User.objects.get(email=email)
            if not doctor.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

        except models.User.DoesNotExist:
            message = "Doctor with this email does not exist."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Send OTP for password reset
        try:
            utils.send_otp_for_password_reset(email, user_type="doctor")
            message = "OTP has been sent to your email."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except ValueError as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Doctor (Confirm Reset Password) *** #
class DoctorConfirmResetPasswordView(APIView):
    """
    This view allows a doctor to reset their password after OTP verification.
    """

    def post(self, request):
        otp = request.data.get("otp")
        password = request.data.get("password")
        password2 = request.data.get("password2")

        if password != password2:
            message = "Passwords do not match."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Validate OTP
        try:
            otp_instance = models.OneTimeOTP.objects.get(otp=otp, user__isnull=False)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        if otp_instance.is_expired():
            message = "OTP has expired."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        doctor = otp_instance.user
        password = password

        doctor.set_password(password)
        doctor.save()
        utils.send_reset_password_confirm(doctor)

        # Delete the used OTP
        models.OneTimeOTP.objects.filter(user=doctor).delete()

        doctor_data = serializers.UserSerializer(doctor).data
        message = "Confirm Reset Password Successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            doctor_data,
        )


# *****************************************************************
# =================================================================
# *** Staff *** #
# *** 3) Staff (Register) *** #
class StaffRegisterView(generics.CreateAPIView):
    queryset = models.User.objects.all()
    serializer_class = serializers.StaffRegisterSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = serializers.StaffRegisterSerializer(data=request.data)

        if serializer.is_valid():
            # Step 1: Save the user data using the serializer's create method
            staff = serializer.save()
            staff_data = serializers.UserSerializer(staff).data

            # Step 2: Send OTP to the staff's email using the utility function
            try:
                # Call the email-sending function
                utils.send_otp_for_user(staff.email, "staff")
            except SMTPRecipientsRefused as e:
                raise ValidationError(
                    {
                        "Error": f"Error sending OTP to {staff.email}: {e}",
                    }
                )

            # Step 3: Return success response
            message = (
                "Staff registered successfully, and We have sent an OTP to your Email!"
            )
            return utils.FunReturn(
                0,
                message,
                status.HTTP_201_CREATED,
                staff_data,
            )

        # Step 4:
        message = serializer.errors
        return utils.FunReturn(1, message, status.HTTP_400_BAD_REQUEST)


# *** Staff (Profile) *** #
class StaffProfileView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.StaffProfileSerializer

    def get_queryset(self):
        return models.StaffProfile.objects.all()

    def get_object(self):
        try:
            staff_pk = self.kwargs["pk"]  # 1
            staff_profile = models.StaffProfile.objects.get(user=staff_pk)
            return staff_profile
        except models.StaffProfile.DoesNotExist:
            status_code = status.HTTP_404_NOT_FOUND
            raise NotFound(
                {
                    "success": "False",
                    "code": 1,
                    "message": "Staff Profile not found",
                    "status_code": status_code,
                    "data": "",
                }
            )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        staff_data = serializer.data

        if staff_data["staff"]["is_staff"] == False:
            message = "Staff Profile whit this id is not Found"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Staff Profile retrieved successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            staff_data,
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        staff_data = serializer.data
        message = "Staff Profile updated successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            staff_data,
        )


# *** Staff (Resend OTP) *** #
class StaffResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = serializers.StaffResendOTPSerializer(data=request.data)

        if not serializer.is_valid():
            message = serializer.errors
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data["email"]
        try:
            user = models.User.objects.get(email=email)

            # Check if the doctor is already verified
            if user.is_verified:
                message = "Your account has already been verified. Please go to the login page."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Resend OTP if not verified
            utils.send_otp_for_user(user.email, "staff")
        except models.User.DoesNotExist:
            message = "No user found with this email."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "OTP has been resent to your email."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
        )


# *** Staff (Verify Account) *** #
class StaffVerifyAccountView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp_code = request.data.get("otp_code")

        # Ensure OTP code is provided
        if not otp_code:
            message = "OTP code is required"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Retrieve the OTP record from OneTimeOTP model
            otp = models.OneTimeOTP.objects.get(otp=otp_code)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP Code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check OTP expiration
        if otp.is_expired():
            message = "OTP has expired"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Determine if the OTP belongs to a User
        if otp.user:
            user = otp.user
        else:
            message = "No associated user for this OTP code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check if the user is already verified
        if user.is_verified:
            message = "Email already verified"
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                user,
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

        staff_data = serializers.UserSerializer(user).data
        message = "Email verified successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            staff_data,
        )


# *** Staff (Login) *** #
class StaffLoginView(APIView):
    def post(self, request):
        # Deserialize the staff login data
        serializer = serializers.StaffLoginSerializer(data=request.data)

        if serializer.is_valid():
            staff = serializer.validated_data  # Extract the validated staff

            if not staff.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                    staff_data,
                )

            # Generate refresh token and include staff_id in the token payload
            refresh = RefreshToken.for_user(staff)
            refresh["staff_id"] = (
                staff.id
            )  # Explicitly add staff_id to the token payload

            # Generate access token
            access_token = refresh.access_token

            staff_data = serializers.UserSerializer(staff).data
            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Invalid OTP Code",
                "status_code": status_code,
                "data": staff_data,
                "access_token": str(access_token),
                "refresh_token": str(refresh),
            }
            return Response(
                response,
                status=status_code,
            )

        message = serializer.errors
        return utils.FunReturn(
            1,
            message,
            status.HTTP_400_BAD_REQUEST,
        )


# *** Staff (ID) *** #
class StaffIDView(APIView):
    def get(self, request, pk):
        try:
            staff = models.User.objects.get(pk=pk)
        except models.User.DoesNotExist:
            message = "Staff not found."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        staff_data = serializers.UserSerializer(staff).data

        if staff_data["is_staff"] == False:
            message = "Staff with this Id is not Found."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Staff retrieved successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            staff_data,
        )


# *** Staff (Refresh) *** #
class StaffRefreshView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = {
                    "refresh_token": "This field is required.",
                }
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_404_NOT_FOUND,
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

            # Fetch the Staff object
            staff = models.User.objects.get(id=user_id)

            # Serialize the Staff object
            staff_data = serializers.UserSerializer(staff).data
            message = "Staff retrieved successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                staff_data,
            )

        except models.User.DoesNotExist:
            raise ValidationError(
                {
                    "message": "Staff not found.",
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


# *** Staff (Change Password) *** #
class StaffChangePasswordView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")

            if not refresh_token:
                raise ValidationError({"refresh_token": "This field is required."})

            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
            staff_id = payload.get("staff_id")

            # Fetch the staff
            staff = models.User.objects.get(id=staff_id)

            # Validate old password
            old_password = request.data.get("old_password")

            if not old_password or not check_password(old_password, staff.password):
                raise ValidationError({"message": "Old password is incorrect."})

            # Validate new passwords
            new_password = request.data.get("new_password")
            confirm_password = request.data.get("confirm_password")

            # validate_password(new_password, confirm_password)

            # Change password
            staff.set_password(new_password)
            staff.save()
            utils.send_change_password_confirm(staff)

            staff_data = serializers.UserSerializer(staff).data
            message = "Password changed successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                staff_data,
            )

        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValidationError("Invalid token")
        except models.User.DoesNotExist:
            raise ValidationError("Staff not found")
        except ValidationError as e:
            message = e.detail
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Staff (Logout) *** #
class StaffLogoutView(APIView):
    def post(self, request):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = "Refresh token not provided."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_400_BAD_REQUEST,
                )

            # Decode the refresh token
            token = RefreshToken(refresh_token)
            staff_id_in_token = token.payload.get("user_id")

            if not staff_id_in_token:
                message = "Invalid token: user id missing."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Validate that the staff exists and matches the current authenticated staff
            staff = models.User.objects.filter(id=staff_id_in_token).first()
            if not staff:
                message = "Invalid token: staff not found."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Expire the token (logout the staff)
            token.set_exp()

            message = "Logout successful."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except Exception as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Staff (Reset Password) *** #
class StaffPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get("email")

        if not email:
            message = "Email is required."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )
        try:
            staff = models.User.objects.get(email=email)
            if not staff.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

        except models.User.DoesNotExist:
            message = "Admin with this email does not exist."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Send OTP for password reset
        try:
            utils.send_otp_for_password_reset(email, user_type="staff")
            message = "OTP has been sent to your email."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except ValueError as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Staff (Confirm Reset Password) *** #
class StaffConfirmResetPasswordView(APIView):
    """
    This view allows a staff to reset their password after OTP verification.
    """

    def post(self, request):
        otp = request.data.get("otp")
        password = request.data.get("password")
        password2 = request.data.get("password2")

        if password != password2:
            message = "Passwords do not match."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Validate OTP
        try:
            otp_instance = models.OneTimeOTP.objects.get(otp=otp, user__isnull=False)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        if otp_instance.is_expired():
            message = "OTP has expired."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        staff = otp_instance.user
        password = password

        staff.set_password(password)
        staff.save()
        utils.send_reset_password_confirm(staff)

        # Delete the used OTP
        models.OneTimeOTP.objects.filter(user=staff).delete()

        staff_data = serializers.UserSerializer(staff).data
        message = "Confirm Reset Password Successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            staff_data,
        )


# *****************************************************************
# =================================================================
# *** 4) Paitent *** #
# *** Paitent (Register) *** #
class PaitentRegisterView(generics.CreateAPIView):
    queryset = models.User.objects.all()
    serializer_class = serializers.PaitentRegisterSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = serializers.PaitentRegisterSerializer(data=request.data)

        if serializer.is_valid():
            # Step 1: Save the user data using the serializer's create method
            paitent = serializer.save()
            paitent_data = serializers.UserSerializer(paitent).data

            # Step 2: Send OTP to the paitent's email using the utility function
            try:
                # Call the email-sending function
                utils.send_otp_for_user(paitent.email, "paitent")
            except SMTPRecipientsRefused as e:
                # Handle invalid email error
                # error_messages = str(e.recipients)
                # print(f"Error sending OTP to {paitent.email}: {error_messages}")
                raise ValidationError(
                    {
                        "Error": "Invald Email",
                    }
                )

            # Step 3: Return success response
            message = "paitent registered successfully, and We have sent an OTP to your Email!"
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                paitent_data,
            )

        message = serializer.errors
        return utils.FunReturn(
            1,
            message,
            status.HTTP_400_BAD_REQUEST,
        )


# *** Paitent (Profile) *** #
class PaitentProfileView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.PaitentProfileSerializer

    def get_queryset(self):
        return models.PaitentProfile.objects.all()

    def get_object(self):
        try:
            paitent_pk = self.kwargs["pk"]  # 1
            paitent_profile = models.PaitentProfile.objects.get(user=paitent_pk)
            return paitent_profile
        except models.PaitentProfile.DoesNotExist:
            status_code = status.HTTP_404_NOT_FOUND
            raise NotFound(
                {
                    "success": "False",
                    "code": 1,
                    "message": "Paitent Profile not found",
                    "status_code": status_code,
                    "data": "",
                }
            )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        paitent_data = serializer.data

        if paitent_data["paitent"]["is_paitent"] == False:
            message = "Paitent Profile whit this id is not Found"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Paitent Profile retrieved successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            paitent_data,
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        paitent_data = serializer.data
        message = "Paitent Profile updated successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            paitent_data,
        )


# *** Paitent (Resend OTP) *** #
class PaitentResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = serializers.PaitentResendOTPSerializer(data=request.data)

        if not serializer.is_valid():
            message = serializer.errors
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        email = serializer.validated_data["email"]
        try:
            user = models.User.objects.get(email=email)

            # Check if the doctor is already verified
            if user.is_verified:
                message = "Your account has already been verified. Please go to the login page."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Resend OTP if not verified
            utils.send_otp_for_user(user.email, "paitent")
        except models.User.DoesNotExist:
            message = "No user found with this email."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "OTP has been resent to your email."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
        )


# *** Paitent (Verify Account) *** #
class PaitentVerifyAccountView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp_code = request.data.get("otp_code")

        # Ensure OTP code is provided
        if not otp_code:
            message = "OTP code is required"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Retrieve the OTP record from OneTimeOTP model
            otp = models.OneTimeOTP.objects.get(otp=otp_code)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP Code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check OTP expiration
        if otp.is_expired():
            message = "OTP has expired"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Determine if the OTP belongs to a User
        if otp.user:
            user = otp.user
        else:
            message = "No associated user for this OTP code"
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Check if the user is already verified
        if user.is_verified:
            message = "Email verified successfully"
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                user,
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

        doctor_data = serializers.UserSerializer(user).data
        message = "Email verified successfully"
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            doctor_data,
        )


# *** Paitent (Login) *** #
class PaitentLoginView(APIView):
    def post(self, request):
        # Deserialize the paitent login data
        serializer = serializers.PaitentLoginSerializer(data=request.data)

        if serializer.is_valid():
            paitent = serializer.validated_data  # Extract the validated paitent

            if not paitent.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Generate refresh token and include paitent_id in the token payload
            refresh = RefreshToken.for_user(paitent)
            refresh["paitent_id"] = (
                paitent.id
            )  # Explicitly add paitent_id to the token payload

            # Generate access token
            access_token = refresh.access_token

            paitent_data = serializers.UserSerializer(paitent).data
            status_code = status.HTTP_200_OK
            response = {
                "success": "True",
                "code": 0,
                "message": "Invalid OTP Code",
                "status_code": status_code,
                "data": paitent_data,
                "access_token": str(access_token),
                "refresh_token": str(refresh),
            }
            return Response(
                response,
                status=status_code,
            )

        message = serializer.errors
        return utils.FunReturn(
            1,
            message,
            status.HTTP_400_BAD_REQUEST,
        )


# *** Paitent (ID) *** #
class PaitentIDView(APIView):
    def get(self, request, pk):
        try:
            paitent = models.User.objects.get(pk=pk)
        except models.User.DoesNotExist:
            message = "Paitent not found."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        # تحويل الكائن إلى JSON باستخدام Serializer
        paitent_data = serializers.UserSerializer(paitent).data

        if paitent_data["is_paitent"] == False:
            message = "Paitent with this Id is not Found."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_404_NOT_FOUND,
            )

        message = "Paitent retrieved successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            paitent_data,
        )


# *** Paitent (Refresh) *** #
class PaitentRefreshView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = (
                    {
                        "refresh_token": "This field is required.",
                    },
                )
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_404_NOT_FOUND,
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

            # Fetch the Paitent object
            paitent = models.User.objects.get(id=user_id)

            # Serialize the Paitent object
            paitent_data = serializers.UserSerializer(paitent).data
            message = "paitent retrieved successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                paitent_data,
            )

        except models.User.DoesNotExist:
            raise ValidationError(
                {
                    "message": "Paitent not found.",
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


# *** Paitent (Change Password) *** #
class PaitentChangePasswordView(APIView):
    def post(self, request):
        try:
            # Retrieve and decode the refresh token
            refresh_token = request.data.get("refresh_token")

            if not refresh_token:
                raise ValidationError({"refresh_token": "This field is required."})

            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
            paitent_id = payload.get("paitent_id")

            # Fetch the paitent
            paitent = models.User.objects.get(id=paitent_id)

            # Validate old password
            old_password = request.data.get("old_password")

            if not old_password or not check_password(old_password, paitent.password):
                raise ValidationError({"message": "Old password is incorrect."})

            # Validate new passwords
            new_password = request.data.get("new_password")
            confirm_password = request.data.get("confirm_password")

            # validate_password(new_password, confirm_password)

            # Change password
            paitent.set_password(new_password)
            paitent.save()
            utils.send_change_password_confirm(paitent)

            paitent_data = serializers.UserSerializer(paitent).data
            message = "Password changed successfully."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
                paitent_data,
            )
        except jwt.ExpiredSignatureError:
            raise ValidationError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValidationError("Invalid token")
        except models.User.DoesNotExist:
            raise ValidationError("Paitent not found")
        except ValidationError as e:
            message = e.detail
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Paitent (Logout) *** #
class PaitentLogoutView(APIView):
    def post(self, request):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                message = "Refresh token not provided."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_400_BAD_REQUEST,
                )

            # Decode the refresh token
            token = RefreshToken(refresh_token)
            paitent_id_in_token = token.payload.get("user_id")

            if not paitent_id_in_token:
                message = "Invalid token: user id missing."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Validate that the paitent exists and matches the current authenticated paitent
            paitent = models.User.objects.filter(id=paitent_id_in_token).first()
            if not paitent:
                message = "Invalid token: paitent not found."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

            # Expire the token (logout the paitent)
            token.set_exp()

            message = "Logout successful."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except Exception as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Paitent (Reset Password) *** #
class PaitentPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get("email")

        if not email:
            message = "Email is required."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )
        try:
            paitent = models.User.objects.get(email=email)
            if not paitent.is_verified:
                message = "Your account is not verified. Please verify your account to proceed."
                return utils.FunReturn(
                    1,
                    message,
                    status.HTTP_403_FORBIDDEN,
                )

        except models.User.DoesNotExist:
            message = "Paitent with this email does not exist."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Send OTP for password reset
        try:
            utils.send_otp_for_password_reset(email, user_type="paitent")
            message = "OTP has been sent to your email."
            return utils.FunReturn(
                0,
                message,
                status.HTTP_200_OK,
            )
        except ValueError as e:
            message = str(e)
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )


# *** Paitent (Confirm Reset Password) *** #
class PaitentConfirmResetPasswordView(APIView):
    """
    This view allows a Paitent to reset their password after OTP verification.
    """

    def post(self, request):
        otp = request.data.get("otp")
        password = request.data.get("password")
        password2 = request.data.get("password2")

        if password != password2:
            message = "Passwords do not match."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        # Validate OTP
        try:
            otp_instance = models.OneTimeOTP.objects.get(otp=otp, user__isnull=False)
        except models.OneTimeOTP.DoesNotExist:
            message = "Invalid OTP."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        if otp_instance.is_expired():
            message = "OTP has expired."
            return utils.FunReturn(
                1,
                message,
                status.HTTP_400_BAD_REQUEST,
            )

        paitent = otp_instance.user
        password = password

        paitent.set_password(password)
        paitent.save()
        utils.send_reset_password_confirm(paitent)

        # Delete the used OTP
        models.OneTimeOTP.objects.filter(user=paitent).delete()

        paitent_data = serializers.UserSerializer(paitent).data
        message = "Confirm Reset Password Successfully."
        return utils.FunReturn(
            0,
            message,
            status.HTTP_200_OK,
            paitent_data,
        )


# *****************************************************************
# =================================================================
# ***  *** #
