from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from auth_system.models import SecurityLog
from django.utils import timezone

@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    SecurityLog.objects.create(
        user=user,
        event_type='login',
        status='success',
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT'),
        timestamp=timezone.now()
    )

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    SecurityLog.objects.create(
        user=user,
        event_type='logout',
        status='success',
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT'),
        timestamp=timezone.now()
    )