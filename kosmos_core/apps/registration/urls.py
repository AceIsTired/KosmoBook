from django.urls import path, include 
from . import views

app_name = 'registration'

urlpatterns = [
    path("register/", views.register, name = "register"),
    path("profile/", views.profile, name = "profile"),
]
