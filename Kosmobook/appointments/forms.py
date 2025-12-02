from django import forms
from .models import Appointment

class AppointmentForm(forms.ModelForm):
    class Meta:
        model = Appointment
        fields = ["scheduled_time", "duration_minutes"]
        # Optional: hard-limit choices to 30 or 60 for the demo
        widgets = {
            # You can add HTML5 datetime-local if you want: forms.DateTimeInput(attrs={"type": "datetime-local"})
        }

    def clean(self):
        cleaned = super().clean()
        # If you want to enforce only 30/60 here instead of the model:
        # dur = cleaned.get("duration_minutes")
        # if dur and dur not in (30, 60):
        #     raise forms.ValidationError("Appointments must be 30 or 60 minutes long.")
        return cleaned
