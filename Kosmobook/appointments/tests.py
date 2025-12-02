from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.appointments.models import Appointment

User = get_user_model()

class AppointmentActionsTest(TestCase):

    def setUp(self):
        self.client_user = User.objects.create_user(
            username="client", password="pass"
        )
        self.prof_user = User.objects.create_user(
            username="pro", password="pass"
        )

        self.appt = Appointment.objects.create(
            client=self.client_user,
            professional=self.prof_user,
            scheduled_time=timezone.now() + timezone.timedelta(hours=2),
            duration_minutes=30,
            status="pending"
        )

    def test_professional_can_confirm(self):
        self.client.login(username="pro", password="pass")
        url = reverse("confirm_appointment", args=[self.appt.id])

        response = self.client.get(url)
        self.appt.refresh_from_db()

        self.assertEqual(self.appt.status, "confirmed")
        self.assertEqual(response.status_code, 302)

    def test_client_cannot_cancel_after_start(self):
        # Move appointment to the past
        self.appt.scheduled_time = timezone.now() - timezone.timedelta(hours=1)
        self.appt.save()

        self.client.login(username="client", password="pass")
        url = reverse("cancel_appointment", args=[self.appt.id])

        response = self.client.get(url)
        self.appt.refresh_from_db()

        # Should NOT change to cancelled
        self.assertNotEqual(self.appt.status, "cancelled")
        self.assertEqual(response.status_code, 302)

    def test_edit_appointment_updates_time(self):
        self.client.login(username="client", password="pass")

        new_time = timezone.now() + timezone.timedelta(hours=5)
        url = reverse("edit_appointment", args=[self.appt.id])

        response = self.client.post(url, {
            "scheduled_time": new_time.strftime("%Y-%m-%dT%H:%M"),
            "duration_minutes": 60
        })

        self.appt.refresh_from_db()

        self.assertEqual(self.appt.duration_minutes, 60)

        # compare YYYY-MM-DD HH:MM (ignoring seconds)
        self.assertEqual(
            self.appt.scheduled_time.replace(second=0, microsecond=0),
            new_time.replace(second=0, microsecond=0)
        )

        self.assertEqual(response.status_code, 302)
