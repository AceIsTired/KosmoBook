from django import forms
from django.utils import timezone
from .models import Appointment

class AppointmentForm(forms.ModelForm):
    # Add a custom field for the datetime input
    scheduled_time = forms.DateTimeField(
        input_formats=['%Y-%m-%dT%H:%M'],
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        label='Date & Time'
    )
    
    class Meta:
        model = Appointment
        fields = ['scheduled_time', 'duration_minutes', 'location', 'status']
        widgets = {
            'duration_minutes': forms.NumberInput(attrs={'min': 15, 'max': 240, 'step': 15}),
            'location': forms.TextInput(attrs={'placeholder': 'Enter appointment location'}),
            'status': forms.HiddenInput(),
        }
        labels = {
            'duration_minutes': 'Duration (minutes)',
            'location': 'Location',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set minimum datetime for the input (current time + 1 hour)
        now = timezone.localtime(timezone.now())
        min_datetime = now.replace(minute=0, second=0, microsecond=0)
        # Add 1 hour for minimum notice
        min_datetime = min_datetime + timezone.timedelta(hours=1)
        
        # Format for HTML datetime-local input
        min_datetime_str = min_datetime.strftime('%Y-%m-%dT%H:%M')
        self.fields['scheduled_time'].widget.attrs['min'] = min_datetime_str

    def clean_scheduled_time(self):
        """Convert local datetime to UTC for storage"""
        scheduled_time = self.cleaned_data.get('scheduled_time')
        if scheduled_time:
            # The datetime from form is naive (no timezone)
            # We need to make it aware and convert to UTC
            from django.utils import timezone
            
            # First, assume it's in the local timezone
            local_tz = timezone.get_current_timezone()
            scheduled_time = scheduled_time.replace(tzinfo=local_tz)
            
            # Convert to UTC for storage
            scheduled_time = scheduled_time.astimezone(timezone.utc)
            
            # Validate it's at least 1 hour from now
            now = timezone.now()
            one_hour_from_now = now + timezone.timedelta(hours=1)
            if scheduled_time < one_hour_from_now:
                raise forms.ValidationError(
                    f"Appointment must be at least 1 hour in advance. "
                    f"Current time: {timezone.localtime(now).strftime('%Y-%m-%d %H:%M')}, "
                    f"Selected time: {timezone.localtime(scheduled_time).strftime('%Y-%m-%d %H:%M')}"
                )
            
        return scheduled_time
