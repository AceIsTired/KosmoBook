from django import forms
from .models import PROFESSION_OPTIONS

class UserTypeForm(forms.Form):
    user_type = forms.ChoiceField(
        choices=[
            ('user', 'I\'m looking for beauty services'),
            ('technician', 'I offer beauty services')
        ],
        widget=forms.RadioSelect,
        required=True
    )

class ProfileInfoForm(forms.Form):
    location = forms.CharField(
        max_length=255,
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'City, State'}),
        help_text="This helps us show you relevant local content"
    )

    bio = forms.CharField(
        required=True,
        widget=forms.Textarea(attrs={
            'rows': 3,
            'placeholder': 'Tell us what you\'re interested in...'
        }),
        help_text="What brings you to Kosmobook?"
    )

class TechnicianDetailsForm(forms.Form):
    specialty = forms.ChoiceField(
        choices=PROFESSION_OPTIONS,
        required=True
    )

    years_of_experience = forms.IntegerField(
        min_value=0,
        required=True,
        help_text="About how many years have you been at this?"
    )

    licensed = forms.BooleanField(
        required=False,
        label="I am a licensed professional"
    )