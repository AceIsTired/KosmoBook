from django.contrib import admin
from django.urls import path, include 
from registration import views as registration_views
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect

def redirect_to_login(request):
    return redirect('login')

urlpatterns = [
    path("admin/", admin.site.urls),
    # I think we are going to need these paths
    # path("profile/", registration_views.profile, name = "profile"),
    # path("login/", auth_views.LoginView.as_view(template_name = "registration/login.html"), name = "login")
    # path("logout/", auth_views.LogoutView.as_view(template_name = "registration/logout.html", next_page = "login"), name = "logout")
]