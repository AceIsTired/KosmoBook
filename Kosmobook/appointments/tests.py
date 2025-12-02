from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()

class AppointmentTests(TestCase):

    def setUp(self):
        self.client_user = User.objects.create_user(username="client", password="pass123")
        self.pro_user = User.objects.create_user(username="pro", password="pass123")

    def test_booking_page_loads(self):
        self.client.login(username="client", password="pass123")
        url = reverse("book_appointment", args=[self.pro_user.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_professional_dashboard_loads(self):
        self.client.login(username="pro", password="pass123")
        url = reverse("professional_appointments")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_client_dashboard_loads(self):
        self.client.login(username="client", password="pass123")
        url = reverse("my_appointments")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
