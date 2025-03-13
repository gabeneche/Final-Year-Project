from django.urls import include, path
from . import views
from django.views.generic import TemplateView
from .views import (CustomPasswordResetView, CustomPasswordResetDoneView, CustomPasswordResetConfirmView,
    CustomPasswordResetCompleteView,
)
from django.conf.urls import handler404
from auth_system import views

handler404 = views.custom_404_view

urlpatterns = [
    path('', TemplateView.as_view(template_name='index.html'), name='home'),  # Homepage
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('mfa-verify/', views.mfa_verify, name='mfa_verify'),
    path('select-mfa-method/', views.select_mfa_method, name='select_mfa_method'),
    path('manage-devices/', views.manage_devices, name='manage_devices'),
    path('remove-device/<int:device_id>/', views.remove_device, name='remove_device'),
    path("check-username/", views.check_username, name="check_username"),
    path("check-email/", views.check_email, name="check_email"),
    path("check-phone/", views.check_phone, name="check_phone"),
    path('verification-link-sent/', views.verification_link_sent, name='verification_link_sent'),
    path('resend-verification-email/', views.resend_verification_email, name='resend_verification_email'),
    path('password-reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]