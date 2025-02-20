#
import re
import phonenumbers
import dns.resolver

#
from django.utils.translation import gettext_lazy as _

#
from rest_framework import serializers
from rest_framework.serializers import ValidationError
from rest_framework.exceptions import APIException


# ================================================================
class CustomValidationError(APIException):
    status_code = 400
    default_detail = []
    default_code = "validation_error"

    def __init__(self, detail=None):
        if detail is None:
            detail = []
        self.detail = detail


# ================================================================
def validate_password(password, password2):
    """
    Validates the password and raises CustomValidationError if invalid.
    Returns errors in the format: {'status': '', 'message': ''}
    """
    errors = []

    if password != password2:
        errors.append(
            {
                "status": "error",
                "message": "Passwords do not match.",
            }
        )

    if len(password) < 8:
        errors.append(
            {
                "status": "error",
                "message": "Password must be at least 8 characters long.",
            }
        )

    if not re.search(r"[A-Z]", password):
        errors.append(
            {
                "status": "error",
                "message": "Password must contain at least one uppercase letter.",
            }
        )

    if not re.search(r"[a-z]", password):
        errors.append(
            {
                "status": "error",
                "message": "Password must contain at least one lowercase letter.",
            }
        )

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append(
            {
                "status": "error",
                "message": "Password must contain at least one special character.",
            }
        )

    if re.search(r"\s", password):
        errors.append(
            {
                "status": "error",
                "message": "Password cannot contain spaces.",
            }
        )

    if errors:
        raise CustomValidationError(errors)


# ================================================================
def validate_email(email):
    """
    Validates the email format, local part, and domain.
    Raises CustomValidationError with structured error messages.
    """
    errors = []

    # Check overall email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        errors.append(
            {
                "status": "error",
                "message": "Invalid email format.",
            }
        )

    try:
        local_part, email_domain = email.split("@")
    except ValueError:
        errors.append(
            {
                "status": "error",
                "message": "Invalid email format. Missing '@'.",
            }
        )
        raise CustomValidationError(errors)

    # Validate the local part
    if len(local_part) < 3:
        errors.append(
            {
                "status": "error",
                "message": "The email part before '@' must be at least 3 characters long.",
            }
        )

    if not re.fullmatch(r"[a-zA-Z0-9._]+", local_part):
        errors.append(
            {
                "status": "error",
                "message": "The email part before '@' contains invalid characters. Only letters, digits, dots (.), and underscores (_) are allowed.",
            }
        )

    # Validate the email domain
    try:
        dns.resolver.resolve(email_domain, "MX")
    except dns.resolver.NoAnswer:
        errors.append(
            {
                "status": "error",
                "message": f"The domain {email_domain} does not have valid email servers.",
            }
        )
    # except dns.resolver.NXDOMAIN:
    # errors.append({'status': 'error', 'message': f"The domain {email_domain} does not exist."})
    if errors:
        raise CustomValidationError(errors)


# ================================================================
def validate_first_last_name(first_name, last_name):
    """
    Validates first and last name.
    Returns the first error encountered.
    """
    if not first_name.isalpha():
        raise CustomValidationError(
            {
                "status": "error",
                "message": "First name must contain only alphabetic characters.",
            }
        )
    if not last_name.isalpha():
        raise CustomValidationError(
            {
                "status": "error",
                "message": "Last name must contain only alphabetic characters.",
            }
        )
    if len(first_name) < 2:
        raise CustomValidationError(
            {
                "status": "error",
                "message": "First name must be at least 2 characters long.",
            }
        )
    if len(last_name) < 2:
        raise CustomValidationError(
            {
                "status": "error",
                "message": "Last name must be at least 2 characters long.",
            }
        )


# ================================================================
def validate_phone_number(value):
    """
    Validates the phone number format.
    """
    errors = []

    if value in [None, ""]:
        return

    # If value is a PhoneNumber object, extract the raw input
    if hasattr(value, "raw_input"):
        value = value.raw_input
    # try:
    # Handle phone number validation
    phone = phonenumbers.parse(value, None)  # None means no default region
    if not phonenumbers.is_valid_number(phone):
        errors.append(
            {
                "status": "error",
                "message": "Invalid phone number.",
            }
        )
    # except phonenumbers.NumberParseException:
    #    errors.append({'status': 'error', 'message': "Invalid phone number format."})

    if errors:
        raise CustomValidationError(errors)


# ================================================================
# full_namec
def validate_full_name(value):
    """
    Validates a full name input and splits it into first and last name.
    """
    errors = []

    full_name = value.strip()
    if not full_name:
        errors.append(
            {
                "status": "error",
                "message": "Full name is required.",
            }
        )

    name_parts = full_name.split()
    if len(name_parts) < 2:
        errors.append(
            {
                "status": "error",
                "message": "Please provide both first name and last name.",
            }
        )

    if errors:
        raise CustomValidationError(errors)

    # Return the split names if valid
    return {
        "first_name": name_parts[0],
        "last_name": " ".join(name_parts[1:]),
    }


# ================================================================
