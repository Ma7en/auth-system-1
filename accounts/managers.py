import uuid


#
from django.contrib.auth.models import BaseUserManager
from django.utils.translation import gettext_lazy as _


# =================================================================
class UserManager(BaseUserManager):
    """
    creating a manager for a custom user model
    https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#writing-a-manager-for-a-custom-user-model
    """

    # =================================================================
    def create_user(self, email, first_name, last_name, password=None, **extra_fields):
        """
        Create and return a `User` with an email, username and password.
        """
        if not email:
            raise ValueError(_("Users Must Have an email address"))

        if not first_name or not last_name:
            raise ValueError(_("First and last names are required"))

        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    # =================================================================
    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a `User` with superuser (admin) permissions.
        """
        if password is None:
            # raise TypeError(_("Superusers must have a password."))
            raise ValueError(_("Superusers must have a password."))

        user = self.create_user(email, password, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

    # =================================================================
    def create_adminuser(self, email, password=None, **extra_fields):
        """
        Create and return a `User` with admin (admin) permissions.
        """
        if password is None:
            raise ValueError(_("Admin must have a password."))

        user = self.create_user(email, password, **extra_fields)
        user.is_admin = True
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

    # =================================================================
    def create_doctoruser(self, email, password=None, **extra_fields):
        if password is None:
            raise ValueError(_("Doctors must have a password"))

        user = self.create_user(email, password, **extra_fields)
        user.is_doctor = True
        user.save()
        return user

    # =================================================================
    def create_staffuser(self, email, password=None, **extra_fields):
        if password is None:
            raise ValueError(_("Staff must have a password"))

        user = self.create_user(email, password, **extra_fields)
        user.is_staff = True
        user.save()
        return user

    # =================================================================
    def create_paitentuser(self, email, password=None, **extra_fields):
        if password is None:
            raise ValueError(_("Paitent must have a password"))

        user = self.create_user(email, password, **extra_fields)
        user.is_paitent = True
        user.save()
        return user

    # =================================================================
