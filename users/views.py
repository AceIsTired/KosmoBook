from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.utils import timezone
from .forms import EditProfileForm
from django.http import JsonResponse, HttpResponseBadRequest, Http404


User = get_user_model()

def profile_view(request, username):
    profile_user = get_object_or_404(User, username=username)
    
    is_following = False
    appointment_stats = {}
    
    if request.user.is_authenticated:
        is_following = request.user.is_following(profile_user)
    
    # Calculate appointment stats for technicians
    if profile_user.is_technician:
        # Import here to avoid circular imports
        from appointments.models import Appointment
        
        professional_appointments = profile_user.professional_appointments.all()
        
        appointment_stats = {
            'total': professional_appointments.count(),
            'confirmed': professional_appointments.filter(status='confirmed').count(),
            'completed': professional_appointments.filter(status='completed').count(),
            'upcoming': professional_appointments.filter(
                status='confirmed', 
                scheduled_time__gte=timezone.now()
            ).count() if hasattr(profile_user.professional_appointments, 'filter') else 0,
        }

    return render(request, 'users/profile.html', {
        'profile_user': profile_user,
        'is_following': is_following,
        'appointment_stats': appointment_stats,
    })

@login_required
def edit_profile(request):
    user = request.user

    if request.method == 'POST':
        form = EditProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            return redirect('users:profile', username=user.username)
    else:
        form = EditProfileForm(instance=user)

    return render(request, 'users/edit_profile.html', {
        'form': form
    })

@login_required
@require_POST
def follow_user(request, username):
    """Follow or unfollow a user"""
    if not request.user.is_authenticated:
        return HttpResponseBadRequest("You must be logged in")

    user_to_follow = get_object_or_404(User, username=username)

    if request.user == user_to_follow:
        return HttpResponseBadRequest("You cannot follow yourself")

    if request.user.is_following(user_to_follow):
        # Unfollow
        request.user.unfollow(user_to_follow)
        action = 'unfollowed'
    else:
        # Follow
        request.user.follow(user_to_follow)
        action = 'followed'

    # Return updated counts for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'action': action,
            'following_count': user_to_follow.get_follower_count(),
            'is_following': request.user.is_following(user_to_follow)
        })

    return redirect('users:profile', username=username)

# for shoing followers or following page
@login_required
def connections(request, username, connection_type):
    profile_user = get_object_or_404(User, username=username)

    # Validate connection_type
    if connection_type not in ['followers', 'following']:
        raise Http404("Invalid connection type")

    # Get the appropriate queryset
    if connection_type == 'followers':
        connections_list = profile_user.get_user_followers()
        title = f"{profile_user.username}'s Followers"
    else:  # connection_type == 'following'
        connections_list = profile_user.get_followed_users()
        title = f"{profile_user.username} is Following"

    # Check if current user follows each connection
    connection_data = []
    for user in connections_list:
        is_following = False
        if request.user.is_authenticated:
            is_following = request.user.is_following(user)
        connection_data.append({
            'user': user,
            'is_following': is_following
        })

    return render(request, 'users/connections.html', {
        'profile_user': profile_user,
        'connection_data': connection_data,
        'connection_type': connection_type,
        'title': title
    })

