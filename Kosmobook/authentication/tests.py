from django.test import Client
from django.urls import reverse
from django.contrib.auth import get_user_model



User = get_user_model()

def test_registration(self):
    client = Client()

    response = client.post(reverse('register'), {
        'username': 'newuser',
        'email': 'new@example.com',
        'password1': 'ComplexPass123!',
        'password2': 'ComplexPass123!',
    })

    self.assertTrue(User.objects.filter(username='newuser').exists())
    self.assertRedirects(response, reverse('setup_profile'))

    new_user = User.objects.get(username='newuser')
    self.assertFalse(new_user.is_initialized)



def test_redirect(self):
    client = Client()

    User.objects.create_user(
        username='inituser',
        password='testpass123',
        is_initialized=True
    )

    response = client.post(reverse('login'), {
        'username': 'inituser',
        'password': 'testpass123'
    })

    self.assertRedirects(response, reverse('home'))

    User.objects.create_user(
        username='noninit',
        password='testpass123',
        is_initialized=False
    )

    response = client.post(reverse('login'), {
        'username': 'noninit',
        'password': 'testpass123'
    })

    self.assertRedirects(response, reverse('setup_profile'))
