#
import uuid


#
from datetime import timedelta


#
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator
from django.db.models.signals import post_save
from django.dispatch import receiver


#
from .managers import UserManager


# =================================================================
# *** User *** #
class User(AbstractBaseUser):
    email = models.EmailField(
        # verbose_name="email address",
        max_length=500,
        unique=True,
    )
    first_name = models.CharField(max_length=500)
    last_name = models.CharField(max_length=500)

    username = models.CharField(
        max_length=300,
        null=True,
        blank=True,
    )
    full_name = models.CharField(
        max_length=300,
        null=True,
        blank=True,
    )

    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_doctor = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_patient = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

    def __str__(self):
        return f"{self.id}): ({self.email})"

    def save(self, *args, **kwargs):
        email_username, _ = self.email.split("@")
        if self.first_name and self.last_name:
            self.full_name = self.first_name + " " + self.last_name
        if self.full_name == "" or self.full_name == None:
            self.full_name = email_username
        if self.username == "" or self.username == None:
            self.username = email_username

        super(User, self).save(*args, **kwargs)


# =================================================================
# *** Admin Profile  *** #
class AdminProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="admin_profile",
        unique=False,
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
        null=True,
        blank=True,
    )
    age = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "admin_profile"

    def __str__(self):
        return f"{self.id}): ({self.user.email})"


# def create_user_admin_profile(sender, instance, created, **kwargs):
#     if created:
#         AdminProfile.objects.create(user=instance)


# def save_user_admin_profile(sender, instance, **kwargs):
#     instance.admin_profile.save()


# post_save.connect(create_user_admin_profile, sender=User)
# post_save.connect(save_user_admin_profile, sender=User)


# =================================================================
# *** Doctor Profile *** #
class DoctorProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="doctor_profile",
        unique=False,
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
        null=True,
        blank=True,
    )
    age = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "doctor_profile"

    def __str__(self):
        return (
            f"{self.id}): (Profile: {self.user.email}) - (Phone: {self.phone_number})"
        )


# def create_user_doctor_profile(sender, instance, created, **kwargs):
#     if created:
#         DoctorProfile.objects.create(user=instance)


# def save_user_doctor_profile(sender, instance, **kwargs):
#     instance.doctor_profile.save()


# post_save.connect(create_user_doctor_profile, sender=User)
# post_save.connect(save_user_doctor_profile, sender=User)


# =================================================================
# *** Staff Profile *** #
class StaffProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="staff_profile",
        unique=False,
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
        null=True,
        blank=True,
    )
    age = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "staff_profile"

    def __str__(self):
        return f"{self.id}): ({self.phone_number})"


# def create_user_staff_profile(sender, instance, created, **kwargs):
#     if created:
#         StaffProfile.objects.create(user=instance)


# def save_user_staff_profile(sender, instance, **kwargs):
#     instance.staff_profile.save()


# post_save.connect(create_user_staff_profile, sender=User)
# post_save.connect(save_user_staff_profile, sender=User)


# =================================================================
# *** Patient Profile *** #
class PatientProfile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="patient_profile",
        unique=False,
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
        upload_to="user/patient",
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
        null=True,
        blank=True,
    )

    age = models.PositiveIntegerField(
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    # class Meta:
    #     """
    #     to set table name in database
    #     """
    #     db_table = "patient_profile"

    def __str__(self):
        return f"{self.id}): ({self.phone_number})"


# def create_user_patient_profile(sender, instance, created, **kwargs):
#     if created:
#         PatientProfile.objects.create(user=instance)


# def save_user_patient_profile(sender, instance, **kwargs):
#     instance.patient_profile.save()


# post_save.connect(create_user_patient_profile, sender=User)
# post_save.connect(save_user_patient_profile, sender=User)


# ================================================================
# *** (Verify Account) *** #
class OneTimeOTP(models.Model):
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    otp = models.CharField(max_length=6)
    token = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        # unique=True,
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
