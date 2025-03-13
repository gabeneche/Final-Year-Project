from django.contrib import admin
from .models import CustomUser, SecurityLog, TrustedDevice
import pandas as pd
from django.http import HttpResponse
from reportlab.pdfgen import canvas
from io import BytesIO


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'phone_number', 'mfa_method', 'is_email_verified')
    list_filter = ('mfa_method', 'is_email_verified')
    search_fields = ('email', 'phone_number')
    actions = ['enable_mfa', 'disable_mfa', 'export_as_csv', 'export_as_pdf']

    def enable_mfa(self, request, queryset):
        queryset.update(mfa_method='email')  # Default to email MFA
    enable_mfa.short_description = "Enable MFA for selected users"

    def disable_mfa(self, request, queryset):
        queryset.update(mfa_method='none')
    disable_mfa.short_description = "Disable MFA for selected users"

    def export_as_csv(self, request, queryset):
        df = pd.DataFrame(list(queryset.values('email', 'phone_number', 'mfa_method', 'is_email_verified')))
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=users.csv'
        df.to_csv(path_or_buf=response, index=False)
        return response
    export_as_csv.short_description = "Export selected users as CSV"

    def export_as_pdf(self, request, queryset):
        buffer = BytesIO()
        p = canvas.Canvas(buffer)
        p.drawString(100, 750, "Users Report")
        y = 700
        for user in queryset:
            p.drawString(100, y, f"Email: {user.email}, Phone: {user.phone_number}, MFA: {user.mfa_method}")
            y -= 20
        p.showPage()
        p.save()
        buffer.seek(0)
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename=users.pdf'
        return response
    export_as_pdf.short_description = "Export selected users as PDF"


@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_id', 'created_at', 'expires_at')
    list_filter = ('user', 'expires_at')
    search_fields = ('user__email', 'device_id')


@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'event_type', 'timestamp')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('user__email', 'details')
    actions = ['export_as_csv', 'export_as_pdf']

    def export_as_csv(self, request, queryset):
        df = pd.DataFrame(list(queryset.values('user__email', 'event_type', 'timestamp', 'details')))
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=security_logs.csv'
        df.to_csv(path_or_buf=response, index=False)
        return response
    export_as_csv.short_description = "Export selected logs as CSV"

    def export_as_pdf(self, request, queryset):
        buffer = BytesIO()
        p = canvas.Canvas(buffer)
        p.drawString(100, 750, "Security Logs Report")
        y = 700
        for log in queryset:
            p.drawString(100, y, f"User: {log.user.email}, Event: {log.event_type}, Timestamp: {log.timestamp}")
            y -= 20
        p.showPage()
        p.save()
        buffer.seek(0)
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename=security_logs.pdf'
        return response
    export_as_pdf.short_description = "Export selected logs as PDF"