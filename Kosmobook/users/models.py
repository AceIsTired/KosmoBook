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
    ('other', 'Other'),
]


class CustomUser(AbstractUser):
    date_of_birth = models.DateField(null = True, blank = True)

    bio = models.TextField(blank = True, null = True)
    profile_picture = models.ImageField(upload_to = 'profile_pics/', blank = True, null = True)
    location = models.CharField(max_length = 255, blank = True, null = True)

    # does the set up popup need to happen on next login
    is_initialized = models.BooleanField(default = False)


    is_technician = models.BooleanField(default = False)

    # Django will automatically make a dropdown menu for the options list and make
    # the .get_specialty_display() method to return the proper name. To define more
    # specialties to pick from, just add them to the list above
    specialty = models.CharField(
            max_length = 50,
            choices = PROFESSION_OPTIONS,
            default = '')

    rating = models.FloatField(default = 0.0)
    years_of_experience = models.IntegerField(default = 0)
    licensed = models.BooleanField(default = False)


    # Following system
    following = models.ManyToManyField(
        'self',
        symmetrical=False,
        related_name='followers',
        blank=True
    )

    def __str__(self):
        return self.username

    def follow(self, user):
        self.following.add(user)

    def unfollow(self, user):
        self.following.remove(user)

    def is_following(self, user):
        return self.following.filter(id=user.id).exists()

    def get_followed_count(self):
        return self.following.count()

    def get_follower_count(self):
        return self.followers.count()

    def get_followed_users(self): # everyone this person follows
        return self.following.all()

    def get_user_followers(self): # users who follow this person
        return self.followers.all()