from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class URLCheckForm(forms.Form):
    url=forms.URLField(label="Website URL", max_length=2048,
                       widget=forms.URLInput(attrs={"placeholder":"https://example.com"}))

class RegisterForm(UserCreationForm):
    class Meta:
        model=User
        fields=("username","password1","password2")
