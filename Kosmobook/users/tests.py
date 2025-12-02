from django.contrib.auth import get_user_model
from users.setup_forms import UserTypeForm, ProfileInfoForm, TechnicianDetailsForm


User = get_user_model()

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
        'specialty': 'makeup',
        'years_of_experience': 3,
        'licensed': True
    })
    self.assertTrue(tech_form.is_valid())
    self.assertEqual(tech_form.cleaned_data['specialty'], 'makeup')
    self.assertTrue(tech_form.cleaned_data['licensed'])