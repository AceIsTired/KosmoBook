from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import get_user_model
from .forms import EditProfileForm
from django.contrib.auth.decorators import login_required 

User = get_user_model()

def profile_view(request, username):
    profile_user = get_object_or_404(User, username=username)
    return render(request, 'users/profile.html', {
        'profile_user': profile_user
    })

@login_required
def edit_profile(request):
    user = request.user

    if request.method == 'POST':
        form = EditProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            return redirect('profile', username=user.username)
    else:
        form = EditProfileForm(instance=user)

    return render(request, 'users/edit_profile.html', {
        'form': form
    })
