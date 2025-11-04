from django.test import TestCase, Client
from django.urls import reverse
from apps.users.models import BaseUser

# found these online, done but still editing

# class registration_tests(TestCase):
#     def start(self):
#         self.client = Client()
#         self.register_url = reverse('register')
#         self.valid_user_data = {
#             'username': 'testuser',
#             'email': 'test@example.com',
#             'password1': 'securepassword123',
#             'password2': 'securepassword123',
#         }

#     def test_duplicate_username(self):
#         BaseUser.objects.create_user(
#             username='testuser',
#             email='existing@example.com',
#             password='existingpass123')

#         response = self.client.post(self.register_url, self.valid_user_data)

#         user_count = BaseUser.objects.filter(username='testuser').count()
#         self.assertEqual(user_count, 1)

#     def test_duplicate_email(self):
#         BaseUser.objects.create_user(
#             username='existinguser',
#             email='test@example.com',
#             password='existingpass123')

#         duplicate_email_data = {
#             'username': 'newuser',
#             'email': 'test@example.com',
#             'password1': 'securepassword123',
#             'password2': 'securepassword123',}

#         response = self.client.post(self.register_url, duplicate_email_data)

#         user_count = BaseUser.objects.filter(email='test@example.com').count()
#         self.assertEqual(user_count, 1)
