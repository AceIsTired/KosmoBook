from django.db import models
from django.contrib.auth.models import AbstractUser

PROFESSION_OPTIONS = [
    ('', 'Select a specialty'),
    ('nail_technician', 'Nail Technician'),
    ('esthetician', 'Esthetician'),
    ('makeup_artist', 'Makeup Artist'),
    ('loctician', 'Loctician'),
    ('barber', 'Barber'),
    ('braider', 'Braider'),
    ('hairstylist', 'Hairstylist'),
    ('massage_artist', 'Massage Artist'),
]


class CustomUser(AbstractUser):
    date_of_birth = models.DateField(null = True, blank = True)
    bio = models.TextField(blank = True, null = True)
    profile_picture = models.ImageField(upload_to = 'profile_pics/', blank = True, null = True)

    def __str__(self):
        return self.username


class Technician(CustomUser):

    # Django will automatically make a dropdown menu for the options list and make
    # the .get_specialty_display() method to return the proper name. To define more
    # specialties to pick from, just add them to the list above

    specialty = models.CharField(
        max_length = 50,
        choices = PROFESSION_OPTIONS,
        default = '')

    rating = models.FloatField(default = 0.0)
    location = models.CharField(max_length = 255)
    years_of_experience = models.IntegerField(default = 0)
    licensed = models.BooleanField(default = False)

    def __str__(self):
        return f"{self.username} - {self.specialty}"