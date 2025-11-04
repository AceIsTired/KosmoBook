from django.apps import AppConfig

class NotificationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.appointments"      # <- MUST match the package path on disk
    verbose_name = "Appointments"
