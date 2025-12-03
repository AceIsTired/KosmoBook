from django import forms
from .models import Appointment

class AppointmentForm(forms.ModelForm):
    class Meta:
        model = Appointment
        fields = ['scheduled_time', 'duration_minutes', 'location', 'status']
        widgets = {
            'scheduled_time': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'duration_minutes': forms.NumberInput(attrs={'min': 15, 'max': 240, 'step': 15}),
            'location': forms.TextInput(attrs={'placeholder': 'Enter appointment location'}),
            'status': forms.HiddenInput(),  # Status is set automatically
        }
        labels = {
            'scheduled_time': 'Date & Time',
            'duration_minutes': 'Duration (minutes)',
            'location': 'Location',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make initial datetime match input format
        self.fields["scheduled_time"].input_formats = ["%Y-%m-%dT%H:%M"]
