from django.test import TestCase
from django.contrib.auth import get_user_model
from users.setup_forms import UserTypeForm, ProfileInfoForm, TechnicianDetailsForm
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile

User = get_user_model()

class ProfileViewTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="sphillips",
            password="Tulane2027",
            email="sphillips3@tulane.edu"
        )
        
        self.user.is_initialized = True
        self.user.save()

    # check that the profile page works for users with a profile
    def test_profile_page_loads_successfully(self):
        self.client.login(username="sphillips", password="Tulane2027")

        url = reverse("users:profile", kwargs={"username": self.user.username})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.user.username)

    # error page if there's no user account 
    def test_profile_404_if_user_not_found(self):
        url = reverse("users:profile", kwargs={"username": "unknownuser"})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)


    def test_setup_forms(self):

        user_type_form = UserTypeForm(data={'user_type': 'user'})
        self.assertTrue(user_type_form.is_valid())
        self.assertEqual(user_type_form.cleaned_data['user_type'], 'user')

        profile_form = ProfileInfoForm(data={
            'location': 'Los Angeles, CA',
            'bio': 'I am a beauty enthusiast'
        })
        self.assertTrue(profile_form.is_valid())
        self.assertEqual(profile_form.cleaned_data['location'], 'Los Angeles, CA')

        tech_form = TechnicianDetailsForm(data={
            'specialty': 'other',
            'years_of_experience': 3,
            'licensed': True
        })
        self.assertTrue(tech_form.is_valid())
        self.assertEqual(tech_form.cleaned_data['specialty'], 'makeup')
        self.assertTrue(tech_form.cleaned_data['licensed'])


# Some profile tests that we can run once the profile is connected to the home page and login down below

# class EditProfileTests(TestCase):

#     def setUp(self):
#         self.user = User.objects.create_user(
#             username="sphillips",
#             password="Tulane2027",
#             email="sphillips3@tulane.edu"
#         )

#     def test_edit_profile_requires_login(self):
#         url = reverse("edit_profile")
#         response = self.client.get(url)
#         self.assertNotEqual(response.status_code, 200)
#         self.assertEqual(response.status_code, 302)  # redirect to login
#         self.assertIn("/login", response.url)

#     def test_logged_in_user_can_view_edit_page(self):
#         self.client.login(username="sphillips", password="Tulane2027")
#         url = reverse("edit_profile")
#         response = self.client.get(url)
#         self.assertEqual(response.status_code, 200)
#         self.assertContains(response, "form")

#     def test_user_can_update_profile(self):
#         self.client.login(username="sphillips", password="Tulane2027")

#         url = reverse("edit_profile")
#         response = self.client.post(url, {
#             "bio": "Updated bio",
#             "location": "New Orleans",
#             "years_of_experience": 3,
#         })

#         # Reload user from database
#         self.user.refresh_from_db()

#         self.assertEqual(self.user.bio, "Updated bio")
#         self.assertEqual(self.user.location, "New Orleans")
#         self.assertEqual(self.user.years_of_experience, 3)

#     def test_user_can_upload_profile_picture(self):
#         self.client.login(username="sphillips", password="Tulane2027")

#         url = reverse("edit_profile")

#         image = SimpleUploadedFile(
#             "test.jpg",
#             b"fake-image-content",
#             content_type="image/jpeg"
#         )

#         response = self.client.post(url, {
#             "bio": "Updated bio with picture",
#             "profile_picture": image
#         })

#         self.user.refresh_from_db()

#         self.assertIsNotNone(self.user.profile_picture)
#         self.assertIn("test.jpg", self.user.profile_picture.name)