from datetime import timedelta
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model

from apps.appointments.models import Appointment, BUSINESS_START_HOUR, BUSINESS_END_HOUR

User = get_user_model()


def tomorrow_at(hour, minute=0):
    """Return a timezone-aware datetime set to tomorrow at given hour:minute."""
    base = timezone.now() + timedelta(days=1)
    return base.replace(hour=hour, minute=minute, second=0, microsecond=0)


def valid_slot(duration_minutes=30):
    """
    Returns (start, duration) within business hours tomorrow.
    We use 10:00 as a safe default start.
    """
    start = tomorrow_at(max(BUSINESS_START_HOUR + 1, 10))
    return start, duration_minutes


class BookingFeatureTests(TestCase):
    def setUp(self):
        # two users: one professional, one customer
        self.pro = User.objects.create_user(username="pro", password="x")
        self.cust = User.objects.create_user(username="cust", password="x")

    # 1) login required to access booking page
    def test_login_required_to_book(self):
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)  # redirect to login

    # 2) GET renders booking form with professional in context
    def test_get_booking_page_renders(self):
        self.client.login(username="cust", password="x")
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Book with")  # from template
        self.assertContains(resp, self.pro.username)

    # 3) Successful booking creates a record
    def test_successful_booking_creates_record(self):
        self.client.login(username="cust", password="x")
        start, dur = valid_slot(duration_minutes=30)
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.post(url, {"scheduled_time": start, "duration_minutes": dur}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            Appointment.objects.filter(professional=self.pro, client=self.cust, scheduled_time=start).exists()
        )

    # 4) Cannot book in the past
    def test_past_start_is_invalid(self):
        self.client.login(username="cust", password="x")
        start = timezone.now() - timedelta(hours=1)
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.post(url, {"scheduled_time": start, "duration_minutes": 30})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Start time must be in the future.")

    # 5) Duration must be positive
    def test_duration_must_be_positive(self):
        self.client.login(username="cust", password="x")
        start, _ = valid_slot()
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.post(url, {"scheduled_time": start, "duration_minutes": 0})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Duration must be positive.")

    # 6) Start must be within business hours (e.g., 06:00 invalid)
    def test_start_outside_business_hours_rejected(self):
        self.client.login(username="cust", password="x")
        start = tomorrow_at(BUSINESS_START_HOUR - 2 if BUSINESS_START_HOUR >= 2 else 6)
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.post(url, {"scheduled_time": start, "duration_minutes": 30})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "within business hours")

    # 7) End must be within business hours (e.g., 16:45 + 30min => 17:15 invalid)
    def test_end_outside_business_hours_rejected(self):
        self.client.login(username="cust", password="x")
        # choose a start that forces end past 17:00
        late_start_hour = max(BUSINESS_END_HOUR - 1, BUSINESS_END_HOUR - 1)
        start = tomorrow_at(late_start_hour, 45)  # e.g., 16:45 + 30 = 17:15
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.post(url, {"scheduled_time": start, "duration_minutes": 30})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "End time must be within business hours")

    # 8) Overlap is rejected for the same professional
    def test_overlapping_appointments_blocked(self):
        self.client.login(username="cust", password="x")
        start, _ = valid_slot(duration_minutes=60)
        Appointment.objects.create(
            professional=self.pro, client=self.cust, scheduled_time=start, duration_minutes=60
        )
        # Overlap: start 30 min into existing 60 min slot
        overlap_start = start + timedelta(minutes=30)
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.post(url, {"scheduled_time": overlap_start, "duration_minutes": 30})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "overlaps with an existing booking")

    # 9) Same time is fine for a different professional (no cross-provider clash)
    def test_no_overlap_across_different_professionals(self):
        self.client.login(username="cust", password="x")
        other_pro = User.objects.create_user(username="pro2", password="x")
        start, dur = valid_slot()
        Appointment.objects.create(
            professional=other_pro, client=self.cust, scheduled_time=start, duration_minutes=dur
        )
        url = reverse("book_appointment", args=[self.pro.id])
        resp = self.client.post(url, {"scheduled_time": start, "duration_minutes": dur}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            Appointment.objects.filter(professional=self.pro, scheduled_time=start).exists()
        )

    # 10) __str__ contains useful info
    def test_str_representation_is_friendly(self):
        start, dur = valid_slot()
        appt = Appointment.objects.create(
            professional=self.pro, client=self.cust, scheduled_time=start, duration_minutes=dur
        )
        s = str(appt)
        self.assertIn(self.pro.username, s)
        self.assertIn(self.cust.username, s)
        self.assertIn(str(start.year), s)
