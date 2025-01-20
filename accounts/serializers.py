#
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse


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
        extra_kwargs = {
            "password": {
                "write_only": True,
            }
        }


# *****************************************************************
# =================================================================
# *** One Time OTP *** #
class OneTimeOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.OneTimeOTP
        fields = "__all__"


# *****************************************************************
# =================================================================
# *** Admin Profile *** #
class AdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.AdminProfile
        fields = "__all__"


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

    def to_representation(self, instance):
        response = super().to_representation(instance)
        response["doctor"] = UserSerializer(instance.user).data
        return response


# *** Doctor (Register) *** #
class DoctorRegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = models.User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password",
            "password2",
            # "profile",
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
        user = models.User.objects.create_doctoruser(**validated_data)
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
