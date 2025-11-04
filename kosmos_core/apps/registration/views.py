from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
#from django.views.decorators.csrf import csrf_exempt
#from django.http import JsonResponse
from .forms import UserRegisterForm
#import json

# Create your views here.


def register(request):
    if request.method == "POST":
        #data = json.loads(request.body)
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f"Account was successfully created for: {username}.")
            return redirect('login')
    else:
        form = UserRegisterForm()

    return render(request, "registration/register.html", {"form":form}) # taking users to their profile

@login_required
def profile(request):
    return render(request, "registration/profile.html")



