from django import forms
from .models import Appointment

class AppointmentForm(forms.ModelForm):
    class Meta:
        model = Appointment
        exclude = ["status", "client", "professional", "created_at"]
        fields = ["scheduled_time", "duration_minutes"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make initial datetime match input format
        self.fields["scheduled_time"].input_formats = ["%Y-%m-%dT%H:%M"]
