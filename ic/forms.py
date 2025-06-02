# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UploadedFile


class CustomRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True, label="Email")

    class Meta:
        model = User
        fields = ("email", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data["email"]  # Set username as email
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class FileUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['file']


class DirectoryScanForm(forms.Form):
    directory_path = forms.CharField(label="Directory Path", max_length=100)


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )


class EmailAuthenticationForm(forms.Form):
    email = forms.EmailField(label="Email", max_length=254)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)


class URLReputationForm(forms.Form):
    url = forms.URLField(
        label="Enter URL",
        widget=forms.URLInput(attrs={
            "class": "form-control",
            "placeholder": "https://example.com"
        }),
        required=True
    )
