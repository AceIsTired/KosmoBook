# apps/appointments/admin.py
from django.contrib import admin
from .models import Appointment
@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    list_display = ("client", "professional", "scheduled_time", "duration_minutes", "status")
    list_filter = ("status",)
    search_fields = ("client__username", "professional__username")
#admin registration so we can see records in admin 