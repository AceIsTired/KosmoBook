from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser

class UserRegistration(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'username', 'email', 'date_of_birth', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.date_of_birth = self.cleaned_data['date_of_birth']

        user.is_initialized = False
        if commit:
            user.save()
        return user

class EditProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = [
            'username',
            'email',
            'bio',
            'profile_picture',
            'date_of_birth',
            'location',
            'specialty',
            'years_of_experience',
            'licensed',
        ]
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 3}),
        }