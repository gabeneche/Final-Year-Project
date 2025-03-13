from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_index, name='dashboard_index'),
    path('auth-logs/', views.dashboard_auth_logs, name='dashboard_auth_logs'),
    path('mfa-settings/', views.dashboard_mfa_settings, name='dashboard_mfa_settings'),
    path('logout/', views.dashboard_logout, name='dashboard_logout'),
]