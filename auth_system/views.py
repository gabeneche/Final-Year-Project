from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from datetime import timedelta
from .forms import CustomUserCreationForm, MFAMethodForm
from .models import CustomUser, SecurityLog, TrustedDevice
from .utils import generate_device_id, generate_verification_token, verify_token
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)
from django.urls import reverse_lazy
import pyotp
import random
import qrcode
from io import BytesIO
import base64
import logging

logger = logging.getLogger(__name__)


# ====================== Authentication Views ======================
def register(request):
    """Handle user registration."""
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_email_verified = False
            user.save()

            # Send verification email
            token = generate_verification_token(user.email)
            verification_link = f'http://127.0.0.1:8000/auth/verify-email/{token}/'
            try:
                send_mail(
                    'Verify Your Email',
                    f'Click the link to verify your email: {verification_link}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                logger.info("Verification email sent successfully.")
            except Exception as e:
                logger.error(f"Failed to send verification email: {str(e)}")
                form.add_error(None, f"Failed to send verification email: {str(e)}")
                return render(request, 'auth_system/register.html', {'form': form})

            # Store user ID in session for MFA setup after email verification
            request.session['user_id_for_mfa'] = user.id
            logger.info(f"Session data set: user_id_for_mfa = {user.id}")
            return redirect('verification_link_sent')
        else:
            logger.error(f"Form errors: {form.errors}")
            return render(request, 'auth_system/register.html', {'form': form})
    else:
        form = CustomUserCreationForm()
        return render(request, 'auth_system/register.html', {'form': form})


def user_login(request):
    """Handle user login."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if not user.mfa_method:
                messages.error(request, 'Please select an MFA method first.')
                return redirect('select_mfa_method')
            else:
                login(request, user)
                return redirect('mfa_verify')
        else:
            return render(request, 'auth_system/login.html', {'error': 'Invalid credentials'})
    return render(request, 'auth_system/login.html')


def verify_email(request, token):
    """Verify user email using the token."""
    email = verify_token(token)
    if email:
        user = CustomUser.objects.filter(email=email).first()
        if user:
            user.is_email_verified = True
            user.save()
            messages.success(request, 'Email verified successfully! Please log in.')
            return redirect('select_mfa_method')
        else:
            messages.error(request, 'User not found.')
    else:
        messages.error(request, 'Invalid or expired verification link.')
    return redirect('register')


def verification_link_sent(request):
    """Display a page confirming the verification link has been sent."""
    return render(request, 'auth_system/verification_link_sent.html')


def resend_verification_email(request):
    """Resend the verification email."""
    if request.method == 'POST':
        email = request.POST.get('email')
        logger.debug(f"Email submitted: {email}")

        if email:
            users = CustomUser.objects.filter(email=email)
            if users.exists():
                user = users.first()
                logger.debug(f"User found: {user.email}")

                if not user.is_email_verified:
                    token = generate_verification_token(user.email)
                    verification_link = f'http://127.0.0.1:8000/auth/verify-email/{token}/'
                    try:
                        send_mail(
                            'Verify Your Email',
                            f'Click the link to verify your email: {verification_link}',
                            settings.DEFAULT_FROM_EMAIL,
                            [user.email],
                            fail_silently=False,
                        )
                        logger.debug("Verification email sent successfully.")
                        messages.success(request, 'Verification email resent successfully!')
                        return redirect('verification_link_sent')
                    except Exception as e:
                        logger.error(f"Failed to send verification email: {str(e)}")
                        messages.error(request, f"Failed to send verification email: {str(e)}")
                else:
                    logger.debug("Email already verified.")
                    messages.error(request, 'This email has already been verified.')
            else:
                logger.debug("No user found with this email.")
                messages.error(request, 'No user found with this email address.')
        else:
            logger.debug("No email provided.")
            messages.error(request, 'Please provide a valid email address.')

    return render(request, 'auth_system/resend_verification_email.html')


# ====================== MFA Views ======================
@login_required
def select_mfa_method(request):
    """Allow users to select their preferred MFA method."""
    if request.method == 'POST':
        form = MFAMethodForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'MFA method selected successfully!')
            return redirect('login')
    else:
        form = MFAMethodForm(instance=request.user)
    return render(request, 'auth_system/select_mfa_method.html', {'form': form})


@login_required
def setup_authenticator(request):
    """Set up Google Authenticator for MFA."""
    user = request.user
    if user.mfa_method == 'google_authenticator':
        if not user.totp_secret:
            user.totp_secret = pyotp.random_base32()
            user.save()

        # Generate TOTP URI and QR code
        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
            name=user.email,
            issuer_name='MFA Project'
        )
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

        return render(request, 'auth_system/setup_authenticator.html', {
            'qr_code_base64': qr_code_base64,
            'totp_secret': user.totp_secret,
        })
    else:
        messages.warning(request, 'Google Authenticator is not your selected MFA method.')
        return redirect('home')


@login_required
def mfa_verify(request):
    user = request.user
    if request.method == 'POST':
        if 'resend_otp' in request.POST:
            return resend_otp(request)

        otp = request.POST.get('otp')
        if not otp:
            messages.error(request, 'Please enter an OTP.')
            return render(request, 'auth_system/mfa_verify.html')

        if user.mfa_method == 'google_authenticator':
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(otp):
                messages.success(request, 'OTP verified successfully!')
                return redirect('dashboard_index')  # Redirect to the dashboard after successful verification
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                return redirect('mfa_verify')
        else:
            session_otp = request.session.get('otp')
            if not session_otp:
                messages.error(request, 'OTP expired. Please request a new one.')
                return redirect('mfa_verify')

            if otp == session_otp:
                messages.success(request, 'OTP verified successfully!')
                return redirect('dashboard_index')  
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                return redirect('mfa_verify')
    else:
        # Handle GET request
        if not user.mfa_method:
            messages.error(request, 'Please select an MFA method first.')
            return redirect('select_mfa_method')
        return generate_otp(request)

def generate_otp(request):
    user = request.user
    otp = str(random.randint(100000, 999999))
    request.session['otp'] = otp  # Store OTP in the session

    if user.mfa_method == 'email':
        send_mail(
            'Your OTP',
            f'Your OTP is: {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        messages.success(request, 'OTP sent to your email.')
    elif user.mfa_method == 'sms':
        if user.send_sms_otp(otp):
            messages.success(request, 'OTP sent to your phone.')
        else:
            send_mail(
                'Your OTP',
                f'Your OTP is: {otp}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            messages.warning(request, 'Failed to send SMS. OTP sent to your email instead.')
    else:
        messages.error(request, 'Invalid MFA method.')
        return redirect('select_mfa_method')

    return render(request, 'auth_system/mfa_verify.html')

def resend_otp(request):
    user = request.user
    try:
        if user.mfa_method == 'email':
            otp = str(random.randint(100000, 999999))
            request.session['otp'] = otp  # Store the new OTP in the session
            send_mail(
                'Your OTP',
                f'Your OTP is: {otp}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            messages.success(request, 'OTP resent to your email.')
        elif user.mfa_method == 'sms':
            otp = str(random.randint(100000, 999999))
            request.session['otp'] = otp  # Store the new OTP in the session
            if user.send_sms_otp(otp):
                messages.success(request, 'OTP resent to your phone.')
            else:
                send_mail(
                    'Your OTP',
                    f'Your OTP is: {otp}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                messages.warning(request, 'Failed to send SMS. OTP resent to your email instead.')
        else:
            messages.error(request, 'Invalid MFA method.')
            return redirect('select_mfa_method')
    except Exception as e:
        logger.error(f"Failed to resend OTP: {str(e)}")
        messages.error(request, 'Failed to resend OTP. Please try again later.')
    return redirect('mfa_verify')

# ====================== Device Management Views ======================
@login_required
def manage_devices(request):
    """Display a list of trusted devices."""
    trusted_devices = TrustedDevice.objects.filter(user=request.user)
    return render(request, 'auth_system/manage_devices.html', {'trusted_devices': trusted_devices})


@login_required
def remove_device(request, device_id):
    """Remove a trusted device."""
    try:
        device = TrustedDevice.objects.get(id=device_id, user=request.user)
        device.delete()
        messages.success(request, 'Device removed successfully.')
    except TrustedDevice.DoesNotExist:
        messages.error(request, 'Device not found.')
    return redirect('manage_devices')


# ====================== Utility Views ======================
def check_username(request):
    """Check if a username already exists."""
    username = request.GET.get("value", "")
    exists = CustomUser.objects.filter(username=username).exists()
    return JsonResponse({"exists": exists})


def check_email(request):
    """Check if an email already exists."""
    email = request.GET.get("value", "")
    exists = CustomUser.objects.filter(email=email).exists()
    return JsonResponse({"exists": exists})


def check_phone(request):
    """Check if a phone number already exists."""
    phone = request.GET.get("value", "")
    exists = CustomUser.objects.filter(phone_number=phone).exists()
    return JsonResponse({"exists": exists})


# ====================== Password Reset Views ======================
class CustomPasswordResetView(PasswordResetView):
    template_name = 'auth_system/password_reset_form.html'
    email_template_name = 'auth_system/password_reset_email.html'
    success_url = reverse_lazy('password_reset_done')


class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'auth_system/password_reset_done.html'


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'auth_system/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'auth_system/password_reset_complete.html'


# ====================== Error Handling ======================
def custom_404_view(request, exception):
    """Handle 404 errors."""
    return render(request, '404.html', status=404)