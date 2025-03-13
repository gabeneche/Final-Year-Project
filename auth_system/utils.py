import hashlib
from datetime import datetime, timedelta
from django.core.signing import Signer, BadSignature
from django.conf import settings
from sinch import SinchClient
from sinch.domains.verification.exceptions import VerificationException
import logging

logger = logging.getLogger(__name__)

# Initialize the signer for token generation and verification
signer = Signer()

def generate_verification_token(email):
    """
    Generates a signed token for email verification with an expiration time.
    Args:
        email (str): The email address to include in the token.
    Returns:
        str: A signed token containing the email and expiration timestamp.
    """
    # Add a timestamp to the email
    expiration_time = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    data = f"{email}:{expiration_time.timestamp()}"  # Combine email and timestamp
    return signer.sign(data)

def verify_token(token):
    """
    Verifies the signed token and returns the email if valid.
    Args:
        token (str): The signed token to verify.
    Returns:
        str or None: The email address if the token is valid and not expired; otherwise, None.
    """
    try:
        # Unsign the token
        data = signer.unsign(token)
        email, expiration_timestamp = data.split(':')  # Split email and timestamp
        expiration_time = datetime.fromtimestamp(float(expiration_timestamp))

        # Check if the token has expired
        if datetime.utcnow() > expiration_time:
            return None  # Token has expired

        return email
    except (BadSignature, ValueError):
        # Handle invalid or tampered tokens
        return None

def generate_device_id(request):
    """
    Generates a unique device ID based on the user's user-agent and IP address.
    Args:
        request (HttpRequest): The Django request object.
    Returns:
        str: A unique device ID.
    """
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ip_address = request.META.get('REMOTE_ADDR', '')
    unique_string = f"{user_agent}{ip_address}"
    return hashlib.sha256(unique_string.encode()).hexdigest()