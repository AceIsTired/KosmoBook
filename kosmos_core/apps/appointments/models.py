from django.db import models
from apps.users.models import BaseUser

# Create your models here.
class Appointment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
        ('completed', 'Completed'),
    ]

    client = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='client_appointments')
    professional = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='professional_appointments')
    scheduled_time = models.DateTimeField()
    duration_minutes = models.PositiveIntegerField(default=30)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Appointment: {self.client} with {self.professional}"