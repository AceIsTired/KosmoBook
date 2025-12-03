from django.urls import path
from .views import profile_view, edit_profile, follow_user, connections, search_profiles

app_name = 'users'

urlpatterns = [
    path('edit/', edit_profile, name='edit_profile'),
    path('search/', search_profiles, name='search_profiles'),
    path('<str:username>/', profile_view, name='profile'),
    path('<str:username>/follow/', follow_user, name='follow_user'),
    path('<str:username>/<str:connection_type>/', connections, name='connections'),
]