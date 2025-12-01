from django.shortcuts import render, get_object_or_404
from django.contrib.auth import get_user_model

User = get_user_model()

def profile_view(request, username):
    profile_user = get_object_or_404(User, username=username)
    return render(request, 'users/profile.html', {
        'profile_user': profile_user
    })
