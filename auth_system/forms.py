from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser
import phonenumbers

class CustomUserCreationForm(UserCreationForm):
    # Add a country code dropdown
    country_code = forms.ChoiceField(
        choices=[
            ('+234', 'Nigeria (+234)'),
            ('+1', 'USA (+1)'),
            ('+44', 'UK (+44)'),
            # Add more country codes as needed
        ],
        initial='+234'  # Default to Nigeria
    )
    phone_number = forms.CharField(max_length=15, required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'country_code', 'phone_number', 'password1', 'password2']  # Removed 'mfa_method'

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not username.isalnum() and not all(char in '@.+-_' for char in username):
            raise forms.ValidationError("Username can only contain letters, numbers, and @/./+/-/_ characters.")
        return username

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match.")
        return password2

    def clean_phone_number(self):
        country_code = self.cleaned_data.get('country_code')
        phone_number = self.cleaned_data.get('phone_number')

        if phone_number:
            try:
                # Combine country code and phone number
                full_number = f"{country_code}{phone_number}"
                parsed_number = phonenumbers.parse(full_number, None)
                if not phonenumbers.is_valid_number(parsed_number):
                    raise forms.ValidationError("Invalid phone number.")
                # Format the phone number in E.164 format
                return phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
            except phonenumbers.phonenumberutil.NumberParseException:
                raise forms.ValidationError("Invalid phone number format.")
        return phone_number

class MFAMethodForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['mfa_method']
        widgets = {
            'mfa_method': forms.Select(choices=CustomUser.MFA_METHOD_CHOICES),
        }
# Compare this snippet from mfa_project/auth_system/views.py: