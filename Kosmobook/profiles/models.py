from django.db import models
from .models import CustomUser


class Profile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    #bio = 

    def __str__(self):
        return f"{self.user.username}'s Profile"
