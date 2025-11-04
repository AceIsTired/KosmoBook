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
from django.contrib.auth import get_user_model
User = get_user_model()

# Create your tests here.

class RegistrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('registration:register')
        self.login_url = reverse('login')
        self.profile_url = reverse('registration:profile')
        self.logout_url = reverse('logout')

    def test_register_page_loads(self):
        # Test that the register page loads successfully
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'registration/register.html')

    def test_register_user_valid_data(self):
        # Test that a user is created and redirected to login with valid data
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password1': 'complexpassword123',
            'password2': 'complexpassword123',
        }
        response = self.client.post(self.register_url, data)
        
        self.assertRedirects(response, self.login_url)
        user_exists = User.objects.filter(username='testuser').exists()
        self.assertTrue(user_exists)

    def test_register_user_invalid_data(self):
        # Test that invalid data does not create a user
        data = {
            'username': '',
            'email': 'invalid-email',
            'password1': 'pass',
            'password2': 'word',
        }
        response = self.client.post(self.register_url, data)

        self.assertEqual(response.status_code, 200)
        form = response.context.get('form')
        self.assertIsNotNone(form, "Form not found in response context")

        # Check that errors exist for the relevant fields
        self.assertTrue(form.errors.get('username'))
        self.assertTrue(form.errors.get('email'))
        self.assertTrue(form.errors.get('password2'))

        # Check the specific error messages
        self.assertIn("This field is required.", form.errors['username'])
        self.assertIn("Enter a valid email address.", form.errors['email'])
        self.assertIn("The two password fields didn’t match.", form.errors['password2'])
        self.assertEqual(User.objects.count(), 0)

    # the following tests check the login/logout and profile paths that were created in urls.py
    def test_profile_page_redirects_if_not_logged_in(self):
        # Test that the profile page redirects to login if user is not authenticated
        response = self.client.get(self.profile_url)
        self.assertRedirects(response, f"{self.login_url}?next={self.profile_url}")

    def test_profile_page_accessible_if_logged_in(self):
        # Test that the profile page is accessible to authenticated users
        user = User.objects.create_user(username='testuser', password='password123')
        self.client.login(username='testuser', password='password123')

        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'registration/profile.html')

    def test_logout_works(self):
        # Test that logout logs out the user and redirects to login
        user = User.objects.create_user(username='testuser', password='password123')
        self.client.login(username='testuser', password='password123')

        response = self.client.post(self.logout_url)
        self.assertRedirects(response, self.login_url)
        
        # Check user is logged out by trying to access profile
        response = self.client.get(self.profile_url)
        self.assertRedirects(response, f"{self.login_url}?next={self.profile_url}")

    def test_login_fails_with_invalid_credentials(self):
        # Test that login fails with invalid credentials
        login_data = {
            'username': 'nonexistent',
            'password': 'wrongpassword',
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, 200)  # Login page should reload
        self.assertContains(response, "Please enter a correct username and password")

    def test_login_succeeds_with_valid_credentials(self):
        # Test that login works with correct credentials
        user = User.objects.create_user(username='validuser', password='validpassword123')
        login_data = {
            'username': 'validuser',
            'password': 'validpassword123',
        }
        response = self.client.post(self.login_url, login_data)
        self.assertRedirects(response, self.profile_url)

    def test_register_fails_with_duplicate_username(self):
        # Test that registering with a duplicate username generates an error
        User.objects.create_user(username='duplicateuser', password='password123')
        data = {
            'username': 'duplicateuser',
            'email': 'newemail@example.com',
            'password1': 'password123',
            'password2': 'password123',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        form = response.context.get('form')
        self.assertIsNotNone(form, "Form not found in response context")

        self.assertTrue(form.errors.get('username'))
        self.assertIn("A user with that username already exists.", form.errors['username'])

    def test_register_requires_email(self):
        # Test that registration fails if email field is left blank
        data = {
            'username': 'userwithoutemail',
            'email': '',
            'password1': 'password123',
            'password2': 'password123',
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        form = response.context.get('form')
        self.assertIsNotNone(form, "Form not found in response context")

        self.assertTrue(form.errors.get('email'))
        self.assertIn("This field is required.", form.errors['email'])


