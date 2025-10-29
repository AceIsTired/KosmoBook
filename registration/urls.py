from django.contrib import admin
from django.urls import path, include 
from users import views as user_views
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect

def redirect_to_login(request):
    return redirect('login')

urlpatterns = [
    path("admin/", admin.site.urls),
    path("register/", user_views.register, name = "register")
]