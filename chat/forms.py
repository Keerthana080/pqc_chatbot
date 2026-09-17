# chat/forms.py
"""
Just the signup form. Login/logout use Django's built-in views and
forms (django.contrib.auth.views) -- no need to reinvent those.
"""

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class SignUpForm(UserCreationForm):
    """
    Django's UserCreationForm already handles username + password +
    password confirmation, including validation (matching passwords,
    minimum strength checks, etc). We don't touch any of that --
    we only use this form's existence as the trigger point for
    generating a Kyber keypair once the user is actually saved.
    See views.signup_view for where that happens.
    """
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username",)