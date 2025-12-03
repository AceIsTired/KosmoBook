from django.urls import path
from .views import profile_view, edit_profile, follow_user, connections

app_name = 'users'

urlpatterns = [
    path('edit/', edit_profile, name='edit_profile'),
    path('<str:username>/', profile_view, name='profile'),
    path('<str:username>/follow/', follow_user, name='follow_user'),
    path('<str:username>/<str:connection_type>/', connections, name='connections'),
]