from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .forms import UserRegisterForm

# Create your views here.


def register(request):
    form = UserRegisterForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        user = form.save()
        messages.success(request, f"Account was successfully created for: {user.username}.")
        return redirect('login')

    return render(request, "registration/register.html", {"form":form})

@login_required
def profile(request):
    return render(request, "registration/profile.html")



