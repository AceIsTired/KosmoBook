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
            # Let field-level validation handle required-ness
            return
        if self.scheduled_time <= timezone.now():
            raise ValidationError("Start time must be in the future.")

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

        # Start within [9:00, 17:00)
        if not (BUSINESS_START_HOUR <= start.hour < BUSINESS_END_HOUR):
            raise ValidationError(
                "Start time must be within business hours (09:00–17:00)."
            )

        # End within (9:00, 17:00], allow exactly 17:00 end
        if end.hour > BUSINESS_END_HOUR or (
            end.hour == BUSINESS_END_HOUR and end.minute > 0
        ):
            raise ValidationError(
                "End time must be within business hours (09:00–17:00)."
            )

    def _validate_no_overlap(self):
        """
        Ensure there is no overlapping appointment for the same professional.
        """
        if self.scheduled_time is None or self.duration_minutes is None:
            return
        if self.professional_id is None:
            # professional is required for overlap checking
            return

        start = self.scheduled_time
        end = self.end_time

        overlapping_qs = (
            Appointment.objects
            .filter(professional=self.professional)
            .exclude(id=self.id)
            .filter(scheduled_time__lt=end)
        )

        # second-pass filter in Python for accurate end-time comparison
        for appt in overlapping_qs:
            other_end = appt.scheduled_time + timedelta(minutes=appt.duration_minutes)
            if other_end > start:
                raise ValidationError(
                    "This slot overlaps with an existing booking for this cosmetologist."
                )
