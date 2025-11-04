# apps/appointments/views.py
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect, render
from .forms import AppointmentForm

User = get_user_model()

@login_required
def book_appointment(request, professional_id):
    professional = get_object_or_404(User, id=professional_id)
    if request.method == "POST":
        form = AppointmentForm(request.POST)
        # ⚠️ Set these BEFORE is_valid(), so model.clean() has them:
        form.instance.professional = professional
        form.instance.client = request.user

        if form.is_valid():
            appt = form.save(commit=False)  # already has professional/client
            appt.full_clean()               # safe now
            appt.save()
            messages.success(request, "Appointment booked!")
            return redirect("booking_success")
    else:
        form = AppointmentForm()
    return render(request, "appointments/book.html", {"form": form, "professional": professional})

def booking_success(request):
    return render(request, "appointments/success.html")
