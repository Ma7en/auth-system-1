import uuid


#
from datetime import timedelta

#
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator


#
from .managers import UserManager


# =================================================================
# *** User *** #
class User(AbstractBaseUser):
    # id = models.UUIDField(
    #     primary_key=True,
    #     default=uuid.uuid4,
    #     editable=False,
    # )
    email = models.EmailField(
        verbose_name="email address",
        max_length=500,
        unique=True,
    )

    username = models.CharField(max_length=300, null=True, blank=True)
    full_name = models.CharField(max_length=300, null=True, blank=True)

    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_doctor = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_paitent = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    # Tells Django that the UserManager class defined above should manage
    # objects of this type.
    objects = UserManager()

    def __str__(self):
        return f"{self.id}): ({self.email})"

    def save(self, *args, **kwargs):
        # email_username, mobile = self.email.split("@")
        email_username, _ = self.email.split("@")
        if self.full_name == "" or self.full_name == None:
            self.full_name = email_username
        if self.username == "" or self.username == None:
            self.username = email_username

        super(User, self).save(*args, **kwargs)


# =================================================================
# *** Admin Profile  *** #
class AdminProfile(models.Model):
    # id = models.UUIDField(
    #     primary_key=True,
    #     default=uuid.uuid4,
    #     editable=False,
    # )
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        # related_name="doctor_profile",
    )

    GENDER_CHOICES = (
        ("Male", "Male"),
        ("Female", "Female"),
    )
    gender = models.CharField(
        max_length=30,
        choices=GENDER_CHOICES,
        null=True,
        blank=True,
    )

    image = models.ImageField(
        upload_to="user/admin",
        default="user/default-user.png",
        null=True,
        blank=True,
    )
    phone_number = models.CharField(
        max_length=11,
        validators=[
            RegexValidator(
                regex="^01[0|1|2|5][0-9]{8}$",
                message="Phone must be start 010, 011, 012, 015 and all number contains 11 digits",
            )
        ],
        unique=True,
        null=True,
        blank=True,
    )
    age = models.PositiveIntegerField(
        null=False,
        blank=False,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "admin_profile"

    def __str__(self):
        return f"{self.id}): ({self.phone_number})"


# =================================================================
# *** Doctor Profile *** #
class DoctorProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
    )

    GENDER_CHOICES = (
        ("Male", "Male"),
        ("Female", "Female"),
    )
    gender = models.CharField(
        max_length=30,
        choices=GENDER_CHOICES,
        null=True,
        blank=True,
    )

    image = models.ImageField(
        upload_to="user/doctor",
        default="user/default-user.png",
        null=True,
        blank=True,
    )
    phone_number = models.CharField(
        max_length=11,
        validators=[
            RegexValidator(
                regex="^01[0|1|2|5][0-9]{8}$",
                message="Phone must be start 010, 011, 012, 015 and all number contains 11 digits",
            )
        ],
        unique=True,
        null=True,
        blank=True,
    )
    age = models.PositiveIntegerField(
        null=False,
        blank=False,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "doctor_profile"

    def __str__(self):
        return f"{self.id}): ({self.phone_number})"


# =================================================================
# *** Staff Profile *** #
class StaffProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
    )

    GENDER_CHOICES = (
        ("Male", "Male"),
        ("Female", "Female"),
    )
    gender = models.CharField(
        max_length=30,
        choices=GENDER_CHOICES,
        null=True,
        blank=True,
    )

    image = models.ImageField(
        upload_to="user/staff",
        default="user/default-user.png",
        null=True,
        blank=True,
    )
    phone_number = models.CharField(
        max_length=11,
        validators=[
            RegexValidator(
                regex="^01[0|1|2|5][0-9]{8}$",
                message="Phone must be start 010, 011, 012, 015 and all number contains 11 digits",
            )
        ],
        unique=True,
        null=True,
        blank=True,
    )
    age = models.PositiveIntegerField(
        null=False,
        blank=False,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "staff_profile"

    def __str__(self):
        return f"{self.id}): ({self.phone_number})"


# =================================================================
# *** Paitent Profile *** #
class PaitentProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
    )

    GENDER_CHOICES = (
        ("Male", "Male"),
        ("Female", "Female"),
    )
    gender = models.CharField(
        max_length=30,
        choices=GENDER_CHOICES,
        null=True,
        blank=True,
    )

    image = models.ImageField(
        upload_to="user/paitent",
        default="user/default-user.png",
        null=True,
        blank=True,
    )
    phone_number = models.CharField(
        max_length=11,
        validators=[
            RegexValidator(
                regex="^01[0|1|2|5][0-9]{8}$",
                message="Phone must be start 010, 011, 012, 015 and all number contains 11 digits",
            )
        ],
        unique=True,
        null=True,
        blank=True,
    )

    age = models.PositiveIntegerField(
        null=False,
        blank=False,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "paitent_profile"

    def __str__(self):
        return f"{self.id}): ({self.phone_number})"


# ================================================================
# *** (Verify Account) *** #
class OneTimeOTP(models.Model):
    otp = models.CharField(max_length=6)
    token = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
    )

    # Separate foreign keys for User
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        expiry_time = self.created_at + timedelta(minutes=10)
        return timezone.now() > expiry_time

    def __str__(self):
        if self.user:
            return f"{self.id}): ({self.user.email}) - OTP code"
        return f"{self.id}): {self.otp} OTP Code"


# =================================================================
# ***  *** #
