from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser

class UserRegistration(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'date_of_birth', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.date_of_birth = self.cleaned_data['date_of_birth']
        if commit:
            user.save()
        return user