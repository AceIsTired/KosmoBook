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
    
    @property
    def local_scheduled_time(self):
        """Return scheduled_time in local timezone for display"""
        from django.utils import timezone
        return timezone.localtime(self.scheduled_time)

    def clean(self):
        """
        Validate that the appointment is in the future, has a valid duration,
        respects business hours, and does not overlap with other bookings
        for the same professional.
        """
        self._validate_duration()
        self._validate_business_hours()
        self._validate_no_overlap()

    def _validate_duration(self):
        """Ensure the duration is positive and in 15-minute increments."""
        if self.duration_minutes is None:
            return
        if self.duration_minutes <= 0:
            raise ValidationError("Duration must be positive.")
        if self.duration_minutes % 15 != 0:
            raise ValidationError("Duration must be in 15-minute increments (15, 30, 45, etc.).")
        if self.duration_minutes > 240:
            raise ValidationError("Duration cannot exceed 4 hours (240 minutes).")

    def _validate_business_hours(self):
        """Ensure the appointment starts and ends within business hours (in LOCAL TIME)."""
        if self.scheduled_time is None or self.duration_minutes is None:
            return

        # Convert to local time for business hour checking
        local_start = timezone.localtime(self.scheduled_time)
        local_end = local_start + timedelta(minutes=self.duration_minutes)
        
        # Check if it's a weekday (Monday=0, Friday=4)
        if local_start.weekday() >= 5:
            raise ValidationError(
                f"Appointments are only available Monday to Friday. "
                f"Selected date: {local_start.strftime('%A, %Y-%m-%d')}"
            )

        # Start within [9:00, 17:00) in local time
        if not (BUSINESS_START_HOUR <= local_start.hour < BUSINESS_END_HOUR):
            raise ValidationError(
                f"Start time {local_start.strftime('%H:%M')} is outside business hours "
                f"({BUSINESS_START_HOUR}:00 - {BUSINESS_END_HOUR}:00)."
            )

        # End within (9:00, 17:00], allow exactly 17:00 end
        if local_end.hour > BUSINESS_END_HOUR or (
            local_end.hour == BUSINESS_END_HOUR and local_end.minute > 0
        ):
            raise ValidationError(
                f"End time {local_end.strftime('%H:%M')} is outside business hours "
                f"({BUSINESS_START_HOUR}:00 - {BUSINESS_END_HOUR}:00). "
                f"Try a shorter duration or earlier start time."
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

        # Find appointments that overlap, excluding cancelled ones
        overlapping = Appointment.objects.filter(
            professional=self.professional,
            scheduled_time__lt=end,
            end_time__gt=start
        ).exclude(
            id=self.id
        ).exclude(
            status='cancelled'
        ).exists()

        if overlapping:
            raise ValidationError(
                "This time slot overlaps with an existing booking for this cosmetologist. "
                "Please choose a different time."
            )
