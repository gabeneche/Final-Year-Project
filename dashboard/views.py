from django.contrib import messages  
from django.utils import timezone
from django.contrib.sessions.models import Session
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from auth_system.models import SecurityLog, TrustedDevice
import logging

# Set up logger
logger = logging.getLogger(__name__)

@login_required
def dashboard_index(request):
    try:
        # Fetch data for the overview
        active_sessions = TrustedDevice.objects.filter(user=request.user, expires_at__gt=timezone.now()).count()
        last_login = request.user.last_login.strftime("%B %d, %Y - %H:%M") if request.user.last_login else "Never"
        mfa_status = "Enabled" if request.user.mfa_method else "Disabled"

        context = {
            'active_sessions': active_sessions,
            'last_login': last_login,
            'mfa_status': mfa_status,
        }
        return render(request, 'dashboard/index.html', context)
    except Exception as e:
        logger.error(f"Error in dashboard_index: {str(e)}")
        messages.error(request, 'An error occurred while loading the dashboard.')
        return render(request, 'dashboard/index.html', {})

@login_required
def dashboard_auth_logs(request):
    try:
        # Fetch authentication logs for the current user
        auth_logs = SecurityLog.objects.filter(user=request.user).order_by('-timestamp')
        context = {
            'auth_logs': auth_logs,
        }
        return render(request, 'dashboard/auth-logs.html', context)
    except Exception as e:
        logger.error(f"Error in dashboard_auth_logs: {str(e)}")
        messages.error(request, 'An error occurred while loading authentication logs.')
        return render(request, 'dashboard/auth-logs.html', {})

@login_required
def dashboard_mfa_settings(request):
    try:
        # Fetch MFA settings for the user
        mfa_method = request.user.mfa_method

        context = {
            'mfa_method': mfa_method,
        }
        return render(request, 'dashboard/mfa-settings.html', context)
    except Exception as e:
        logger.error(f"Error in dashboard_mfa_settings: {str(e)}")
        messages.error(request, 'An error occurred while loading MFA settings.')
        return render(request, 'dashboard/mfa-settings.html', {})

@login_required
def dashboard_logout(request):
    try:
        # Log the user out
        logout(request)
        messages.success(request, 'You have been logged out successfully.')
        return redirect('login')  # Redirect to the login page
    except Exception as e:
        logger.error(f"Error in dashboard_logout: {str(e)}")
        messages.error(request, 'An error occurred while logging out.')
        return redirect('login')  # Fallback to the dashboard