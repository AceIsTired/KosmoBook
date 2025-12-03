from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from datetime import timedelta

BUSINESS_START_HOUR = 9
BUSINESS_END_HOUR = 17  # 5pm


class Appointment(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("confirmed", "Confirmed"),
        ("cancelled", "Cancelled"),
        ("completed", "Completed"),
    ]

    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="client_appointments",
    )
    professional = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="professional_appointments",
    )
    scheduled_time = models.DateTimeField()
    duration_minutes = models.PositiveIntegerField(default=30)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        ordering = ["scheduled_time"]

    def __str__(self):
        return (
            f"Appointment: {self.client} with {self.professional} "
            f"@ {self.scheduled_time:%Y-%m-%d %H:%M}"
        )

    @property
    def end_time(self):
        return self.scheduled_time + timedelta(minutes=self.duration_minutes)


    def clean(self):
        """
        Validate that the appointment is in the future, has a valid duration,
        respects business hours, and does not overlap with other bookings
        for the same professional.
        """
        self._validate_future_start()
        self._validate_duration()
        self._validate_business_hours()
        self._validate_no_overlap()

    def _validate_future_start(self):
        """Ensure the appointment start time is in the future."""
        if self.scheduled_time is None:
            return
        
        now = timezone.now()
        # Allow appointments at least 1 hour in the future (minimum notice)
        one_hour_from_now = now + timedelta(hours=1)
        
        if self.scheduled_time < one_hour_from_now:
            raise ValidationError(
                f"Start time must be at least 1 hour in the future. "
                f"Current time: {now.strftime('%Y-%m-%d %H:%M')}, "
                f"Selected time: {self.scheduled_time.strftime('%Y-%m-%d %H:%M')}"
            )

    def _validate_duration(self):
        """Ensure the duration is positive (and optionally constrained)."""
        if self.duration_minutes is None:
            return
        if self.duration_minutes <= 0:
            raise ValidationError("Duration must be positive.")
        # Optional: enforce only 30 or 60 minute slots
        # if self.duration_minutes not in (30, 60):
        #     raise ValidationError("Appointments must be 30 or 60 minutes long.")

    def _validate_business_hours(self):
        """Ensure the appointment starts and ends within business hours."""
        if self.scheduled_time is None or self.duration_minutes is None:
            return

        start = self.scheduled_time
        end = self.end_time
        
        # Check if start time is on a weekday (Mon-Fri)
        if start.weekday() >= 5:  # 5=Saturday, 6=Sunday
            raise ValidationError(
                "Appointments are only available Monday to Friday."
            )
        
        # Start within [9:00, 17:00)
        if not (BUSINESS_START_HOUR <= start.hour < BUSINESS_END_HOUR):
            raise ValidationError(
                f"Start time {start.strftime('%H:%M')} is outside business hours "
                f"({BUSINESS_START_HOUR}:00 - {BUSINESS_END_HOUR}:00)."
            )
        
        # End within (9:00, 17:00], allow exactly 17:00 end
        if end.hour > BUSINESS_END_HOUR or (
            end.hour == BUSINESS_END_HOUR and end.minute > 0
        ):
            raise ValidationError(
                f"End time {end.strftime('%H:%M')} is outside business hours "
                f"({BUSINESS_START_HOUR}:00 - {BUSINESS_END_HOUR}:00). "
                f"Duration might be too long."
            )

    def _validate_no_overlap(self):
        """
    Ensure there is no overlapping appointment for the same professional.
    """
        if self.scheduled_time is None or self.duration_minutes is None:
            return
        if self.professional_id is None:
            return

        start = self.scheduled_time
        end = self.end_time

        # Find appointments that overlap with our time slot
        overlapping = Appointment.objects.filter(
            professional=self.professional
        ).exclude(
            id=self.id  # Exclude self if updating
        ).exclude(
            status='cancelled'  # Exclude cancelled appointments
        ).filter(
            scheduled_time__lt=end,
            end_time__gt=start  # Using property
        ).exists()

        if overlapping:
            raise ValidationError(
                "This time slot overlaps with an existing booking for this cosmetologist."
            )