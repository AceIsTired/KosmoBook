# apps/appointments/models.py
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
    duration_minutes = models.PositiveIntegerField(default=30)  # you can change to choices=[(30,"30"),(60,"60")]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["scheduled_time"]

    def __str__(self):
        return f"Appointment: {self.client} with {self.professional} @ {self.scheduled_time:%Y-%m-%d %H:%M}"

    @property
    def end_time(self):
        return self.scheduled_time + timedelta(minutes=self.duration_minutes)

    def clean(self):
        # 1) must be in the future
        if self.scheduled_time <= timezone.now():
            raise ValidationError("Start time must be in the future.")

        # 2) duration must be positive (you can also enforce 30/60 via choices)
        if self.duration_minutes <= 0:
            raise ValidationError("Duration must be positive.")
        # (Optional) enforce 30 or 60 only:
        # if self.duration_minutes not in (30, 60):
        #     raise ValidationError("Appointments must be 30 or 60 minutes long.")

        # 3) business hours checks (simple same-day window check)
        start = self.scheduled_time
        end = self.end_time

        # start within [9:00, 17:00)
        if not (BUSINESS_START_HOUR <= start.hour < BUSINESS_END_HOUR):
            raise ValidationError("Start time must be within business hours (09:00–17:00).")

        # end within (9:00, 17:00], allow exactly 17:00 end
        if end.hour > BUSINESS_END_HOUR or (end.hour == BUSINESS_END_HOUR and end.minute > 0):
            raise ValidationError("End time must be within business hours (09:00–17:00).")

        # 4) no overlaps for the same professional
        overlapping = Appointment.objects.filter(
            professional=self.professional
        ).exclude(id=self.id).filter(
            scheduled_time__lt=end,
            # any appt whose start is before our end AND whose end is after our start
            # we compute other_end = scheduled_time + duration in DB via inequality trick:
        )

        # We can’t compute other_end in DB easily without ExpressionWrapper;
        # do a second-pass filter in Python for accuracy:
        for appt in overlapping:
            other_end = appt.scheduled_time + timedelta(minutes=appt.duration_minutes)
            if other_end > start:
                raise ValidationError("This slot overlaps with an existing booking for this cosmetologist.")
