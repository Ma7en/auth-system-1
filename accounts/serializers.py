#
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _


#
from rest_framework import status
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import ValidationError

#
from accounts import models
from accounts import utils


# *****************************************************************
# =================================================================
# *** User *** #
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = "__all__"
        # fields = (
        #     "gender",
        #     "image",
        #     "phone_number",
        #     "age",
        # )


# *****************************************************************
# =================================================================
# *** Admin Profile *** #
class AdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.AdminProfile
        fields = "__all__"
        # fields = (
        #     "gender",
        #     "image",
        #     "phone_number",
        #     "age",
        # )


# *** Admin Register *** #
class AdminRegisterSerializer(serializers.ModelSerializer):
    profile = AdminProfileSerializer(required=False)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = models.User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password",
            "password2",
            "profile",
        )
        extra_kwargs = {
            "password": {
                "write_only": True,
            }
        }

    def validate(self, attrs):
        # Define a validation method to check if the passwords match
        if attrs["password"] != attrs["password2"]:
            # Raise a validation error if the passwords don't match
            raise serializers.ValidationError(
                {
                    "password": "Password fields didn't match.",
                }
            )
        # Return the validated attributes
        return attrs

    def create(self, validated_data):
        profile_data = validated_data.pop("profile")
        user = models.User.objects.create_adminuser(**validated_data)
        models.AdminProfile.objects.create(
            user=user,
            gender=profile_data["gender"],
            image=profile_data["image"],
            phone_number=profile_data["phone_number"],
            age=profile_data["age"],
        )
        return user


# *****************************************************************
# =================================================================
# *** Doctor (Profile) *** #
class DoctorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.DoctorProfile
        fields = "__all__"
        # fields = (
        #     "gender",
        #     "image",
        #     "phone_number",
        #     "age",
        # )


# *** Doctor (Register) *** #
class DoctorRegisterSerializer(serializers.ModelSerializer):
    profile = DoctorProfileSerializer(required=False)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = models.User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password",
            "password2",
            "profile",
        )
        extra_kwargs = {
            "password": {
                "write_only": True,
            }
        }

    def validate(self, attrs):
        # Define a validation method to check if the passwords match
        if attrs["password"] != attrs["password2"]:
            # Raise a validation error if the passwords don't match
            raise serializers.ValidationError(
                {
                    "password": "Password fields didn't match.",
                }
            )
        # Return the validated attributes
        return attrs

    def create(self, validated_data):
        profile_data = validated_data.pop("profile")
        user = models.User.objects.create_doctoruser(**validated_data)
        models.DoctorProfile.objects.create(
            user=user,
            gender=profile_data["gender"],
            image=profile_data["image"],
            phone_number=profile_data["phone_number"],
            age=profile_data["age"],
        )
        return user


# *** Doctor (Resend OTP) *** #
class DoctorResendOTPSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = models.User
        fields = ["email"]

    def validate_email(self, value):
        """
        Ensure the email exists in the User model.
        """
        if not models.User.objects.filter(email=value).exists():
            raise serializers.ValidationError(_("No driver found with this email."))
        return value


# *** Doctor (Login) *** #
class DoctorLoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=500)
    password = serializers.CharField(write_only=True)

    # 2
    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        try:
            # Fetch the Doctor by email
            doctor = models.User.objects.get(email=email)
        except models.User.DoesNotExist:
            raise AuthenticationFailed(_("Invalid Email or Password."))

        # Authenticate doctor by verifying the password
        if not doctor.check_password(password):
            raise AuthenticationFailed(_("Invalid Email or Password."))

        # Check if the doctor is active
        if not doctor.is_active:
            raise AuthenticationFailed(_("doctor account is deactivated."))

        return doctor

    # 1
    # def validate(self, data):
    #     # if not data.get("email"):
    #     #     return False

    #     # if not data.get("password"):
    #     #     return False

    #     email = data.get("email", None)
    #     password = data.get("password", None)
    #     user = authenticate(email=email, password=password)
    #     if user is None:
    #         raise serializers.ValidationError(
    #             _("A user with this email and password is not found.")
    #         )

    #     try:
    #         payload = JWT_PAYLOAD_HANDLER(user)
    #         jwt_token = JWT_ENCODE_HANDLER(payload)
    #         update_last_login(None, user)
    #     except User.DoesNotExist:
    #         raise serializers.ValidationError(
    #             "User with given email and password does not exists"
    #         )
    #     return {
    #         "email": user.email,
    #         "token": jwt_token,
    #     }


# Doctor (Reset Password) *** #
class DoctorResetPasswordSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        otp = attrs.get("otp")
        password = attrs.get("password")
        password2 = attrs.get("password2")

        # Validate password strength
        # validate_password(password, password2)

        # Validate OTP
        try:
            otp_instance = models.OneTimeOTP.objects.get(otp=otp, driver__isnull=False)
        except models.OneTimeOTP.DoesNotExist:
            raise ValidationError(_("Invalid OTP."))

        if otp_instance.is_expired():
            raise ValidationError(_("OTP has expired."))

        return {
            "doctor": otp_instance.doctor,
            "password": password,
        }

    def save(self):
        doctor = self.validated_data["doctor"]
        password = self.validated_data["password"]

        # Set the new password
        doctor.set_password(password)
        doctor.save()

        utils.send_reset_password_confirm(doctor)
        # Delete the used OTP
        models.OneTimeOTP.objects.filter(doctor=doctor).delete()

        return doctor


# *****************************************************************
# =================================================================
# *** Staff Profile *** #
class StaffProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.StaffProfile
        fields = "__all__"
        # fields = (
        #     "gender",
        #     "image",
        #     "phone_number",
        #     "age",
        # )


# *** Staff Register *** #
class StaffRegisterSerializer(serializers.ModelSerializer):
    profile = StaffProfileSerializer(required=False)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = models.User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password",
            "password2",
            "profile",
        )
        extra_kwargs = {
            "password": {
                "write_only": True,
            }
        }

    def validate(self, attrs):
        # Define a validation method to check if the passwords match
        if attrs["password"] != attrs["password2"]:
            # Raise a validation error if the passwords don't match
            raise serializers.ValidationError(
                {
                    "password": "Password fields didn't match.",
                }
            )
        # Return the validated attributes
        return attrs

    def create(self, validated_data):
        profile_data = validated_data.pop("profile")
        user = models.User.objects.create_staffuser(**validated_data)
        models.StaffProfile.objects.create(
            user=user,
            gender=profile_data["gender"],
            image=profile_data["image"],
            phone_number=profile_data["phone_number"],
            age=profile_data["age"],
        )
        return user


# *****************************************************************
# =================================================================
# *** Paitent Profile *** #
class PaitentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.PaitentProfile
        fields = "__all__"
        # fields = (
        #     "gender",
        #     "image",
        #     "phone_number",
        #     "age",
        # )


# *** Paitent Register *** #
class PaitentRegisterSerializer(serializers.ModelSerializer):
    profile = PaitentProfileSerializer(required=False)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = models.User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password",
            "password2",
            "profile",
        )
        extra_kwargs = {
            "password": {
                "write_only": True,
            }
        }

    def validate(self, attrs):
        # Define a validation method to check if the passwords match
        if attrs["password"] != attrs["password2"]:
            # Raise a validation error if the passwords don't match
            raise serializers.ValidationError(
                {
                    "password": "Password fields didn't match.",
                }
            )
        # Return the validated attributes
        return attrs

    def create(self, validated_data):
        profile_data = validated_data.pop("profile")
        user = models.User.objects.create_paitentuser(**validated_data)
        models.PaitentProfile.objects.create(
            user=user,
            gender=profile_data["gender"],
            image=profile_data["image"],
            phone_number=profile_data["phone_number"],
            age=profile_data["age"],
        )
        return user


# *****************************************************************
# =================================================================
# *** *** #
