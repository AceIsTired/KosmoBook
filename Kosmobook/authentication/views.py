from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from users.forms import UserRegistration
from users.setup_forms import UserTypeForm, ProfileInfoForm, TechnicianDetailsForm


def landing(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        return render(request, 'auth/landing.html')


def register(request):
    if request.method == 'POST':
        form = UserRegistration(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)

            user.is_initialized = False
            user.save()
            return redirect('setup_profile')
    else:
        form = UserRegistration()

    return render(request, 'auth/register.html', {'form': form})


def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f"Welcome back, {username}!")
                return redirect('home')
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()

    return render(request, 'auth/login.html', {'form': form})

def user_logout(request):
    logout(request)
    messages.info(request, "You have successfully logged out.")
    return redirect('login')


def home(request):
    if not request.user.is_authenticated:
        return redirect('login')

    return render(request, 'users/home.html')


# below are the initialization questions functions

@login_required
def setup_profile(request):
    if request.user.is_initialized:
        return redirect('home')

    # Handle skip setup
    if request.method == 'POST' and 'skip_setup' in request.POST:
        user = request.user
        user.is_initialized = True
        user.save()
        return redirect('home')

    if 'init_data' not in request.session:
        request.session['init_data'] = {}

    # Get current step from GET parameter
    step = request.GET.get('step', '1')

    if request.method == 'POST':
        if step == '1':
            form = UserTypeForm(request.POST)
            if form.is_valid():
                request.session['init_data']['user_type'] = form.cleaned_data['user_type']
                request.session.modified = True

                return redirect('/accounts/setup/?step=2')

        elif step == '2':
            form = ProfileInfoForm(request.POST)
            if form.is_valid():
                request.session['init_data'].update(form.cleaned_data)
                user_type = request.session['init_data'].get('user_type')

                print("USER TYPE:", user_type)

                if user_type == 'technician':

                    return redirect('/accounts/setup/?step=3')
                else:
                    return save_setup(request)

        elif step == '3':
            form = TechnicianDetailsForm(request.POST)
            if form.is_valid():
                request.session['init_data'].update(form.cleaned_data)
                return save_setup(request)

    else:
        if step == '1':
            form = UserTypeForm()
        elif step == '2':
            form = ProfileInfoForm()
        elif step == '3':
            form = TechnicianDetailsForm()
        else:
            return redirect('/accounts/setup/?step=1')

    context = {
        'form': form,
        'step': step,
        'total_steps': 3,
    }

    return render(request, 'auth/userSetup.html', context)

def save_setup(request):
    init_data = request.session.get('init_data', {})
    user = request.user

    user.location = init_data.get('location', '')
    user.bio = init_data.get('bio', '')


    user_type = init_data.get('user_type')
    user.is_technician = (user_type == 'technician')


    if user.is_technician:
        user.specialty = init_data.get('specialty', '')
        user.years_of_experience = init_data.get('years_of_experience', 0)
        user.licensed = init_data.get('licensed', False)

    user.is_initialized = True
    user.save()

    # Clear session data
    if 'init_data' in request.session:
        del request.session['init_data']

    return redirect('home')