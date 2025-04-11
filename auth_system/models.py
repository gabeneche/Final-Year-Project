from django.utils import timezone
from django.conf import settings
import pyotp
from django.contrib.auth.models import AbstractUser
from django.db import models
from sinch import SinchClient
from sinch.domains.verification.models import VerificationIdentity  
from django.core.exceptions import ValidationError
import phonenumbers 
import logging
from django.contrib.auth import get_user_model
from sinch.domains.verification.exceptions import VerificationException  

logger = logging.getLogger(__name__)


class CustomUser(AbstractUser):
    MFA_METHOD_CHOICES = [
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('app', 'Google Authenticator'),
    ]

    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    mfa_method = models.CharField(
        max_length=20,
        choices=MFA_METHOD_CHOICES,
        default='email'
    )
    is_email_verified = models.BooleanField(default=False)
    totp_secret = models.CharField(
        max_length=32,
        blank=True,
        null=True,
        help_text="TOTP secret for Google Authenticator."
    )

    def clean(self):
        """
        Validate and format the phone number to E.164 format before saving.
        """
        super().clean()
        if self.phone_number:
            try:
                # Parse and validate the phone number
                parsed_number = phonenumbers.parse(self.phone_number, None)
                if not phonenumbers.is_valid_number(parsed_number):
                    raise ValidationError("Invalid phone number.")
                # Format the phone number in E.164 format
                self.phone_number = phonenumbers.format_number(
                    parsed_number,
                    phonenumbers.PhoneNumberFormat.E164
                )
            except phonenumbers.phonenumberutil.NumberParseException:
                raise ValidationError("Invalid phone number format.")

    def generate_totp_secret(self):
        """
        Generates a TOTP secret for Google Authenticator.
        """
        self.totp_secret = pyotp.random_base32()
        self.save()

    def get_totp_uri(self):
        """
        Returns the provisioning URI for Google Authenticator.
        """
        if self.totp_secret:
            return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
                self.email,
                issuer_name=settings.MFA_ISSUER_NAME  # Use the issuer name from settings
            )
        return None

    def verify_totp(self, code):
        """
        Verifies a TOTP code entered by the user.
        """
        if self.totp_secret:
            totp = pyotp.TOTP(self.totp_secret)
            return totp.verify(code)
        return False

    def is_mfa_enabled(self):
        """
        Checks if MFA is enabled for the user.
        """
        return self.mfa_method != 'none'  # Assuming 'none' is a valid choice



    def send_sms_otp(self):
        """
        Sends an OTP via SMS using Sinch.
        Returns a boolean indicating success or failure.
        """
        if self.mfa_method == 'sms' and self.phone_number:
            try:
                logger.info(f"Attempting to send SMS to {self.phone_number}")

                # Initialize Sinch client
                sinch_client = SinchClient(
                    application_key=settings.SINCH_APPLICATION_KEY,
                    application_secret=settings.SINCH_APPLICATION_SECRET
                )

                # Generate OTP
                otp = pyotp.TOTP(self.totp_secret).now()

                # Start SMS verification
                response = sinch_client.verification.verifications.start_sms(
                    identity=VerificationIdentity(
                        type="number",
                        endpoint=self.phone_number
                    ),
                    message=f"Your OTP is: {otp}"
                )
                logger.info(f"SMS sent successfully. Verification ID: {response.id}")
                return True  # Success
            except VerificationException as e:
                logger.error(f"Failed to send SMS: {str(e)}")
                return False  # Failure
        else:
            logger.error("SMS MFA is not enabled or phone number is missing.")
            return False  # Failure
    

class TrustedDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=64)  # Unique identifier for the device
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"{self.user.email} - {self.device_id}"

User = get_user_model()

class SecurityLog(models.Model):
    EVENT_TYPES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('mfa_success', 'MFA Success'),
        ('mfa_failure', 'MFA Failure'),
    ]

    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failure', 'Failure'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)  
    event_type = models.CharField(max_length=50)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES)
    ip_address = models.GenericIPAddressField(default='0.0.0.0')  
    user_agent = models.CharField(max_length=255, default='Unknown') 
    timestamp = models.DateTimeField(default=timezone.now)  

    def __str__(self):
        return f"{self.user.username} - {self.event_type} at {self.timestamp}"
