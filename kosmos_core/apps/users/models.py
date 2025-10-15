from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class BaseUser(AbstractUser):
    bio = models.TextField(max_length = 300, blank = True)
    profile_picture = models.URLField(blank = True)

    class Meta:
        app_label = 'users'

    def __str__(self):
        return self.username