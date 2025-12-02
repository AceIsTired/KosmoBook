# apps/appointments/views.py
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect, render
from .forms import AppointmentForm

from django.utils import timezone
from .models import Appointment

from django.http import HttpResponseForbidden



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

@login_required
def professional_appointments(request):
    """
    Dashboard for professionals to see all of their appointments.
    Splits into upcoming vs past for convenience.
    """
    # Only show appointments where the logged-in user is the professional
    qs = Appointment.objects.filter(professional=request.user).order_by("scheduled_time")

    now = timezone.now()
    upcoming_appointments = qs.filter(scheduled_time__gte=now)
    past_appointments = qs.filter(scheduled_time__lt=now)

    context = {
        "upcoming_appointments": upcoming_appointments,
        "past_appointments": past_appointments,
    }
    return render(request, "appointments/professional_appointments.html", context)


@login_required
def my_appointments(request):
    """
    Dashboard for clients to see the appointments they booked.
    Splits into upcoming and past.
    """
    qs = Appointment.objects.filter(client=request.user).order_by("scheduled_time")

    now = timezone.now()
    upcoming_appointments = qs.filter(scheduled_time__gte=now)
    past_appointments = qs.filter(scheduled_time__lt=now)

    context = {
        "upcoming_appointments": upcoming_appointments,
        "past_appointments": past_appointments,
    }
    return render(request, "appointments/my_appointments.html", context)


@login_required
def confirm_appointment(request, appointment_id):
    appt = get_object_or_404(Appointment, id=appointment_id)

    # Only the professional can confirm
    if request.user != appt.professional:
        return HttpResponseForbidden("You do not have permission to confirm this appointment.")

    appt.status = "confirmed"
    appt.save()
    messages.success(request, "Appointment confirmed!")
    return redirect("professional_appointments")


@login_required
def cancel_appointment(request, appointment_id):
    appt = get_object_or_404(Appointment, id=appointment_id)

    # Both client or professional can cancel
    if request.user not in (appt.client, appt.professional):
        return HttpResponseForbidden("You do not have permission to cancel this appointment.")

    # PREVENT CLIENT FROM CANCELING AFTER THE APPOINTMENT STARTS
    from django.utils import timezone
    if request.user == appt.client and appt.scheduled_time <= timezone.now():
        messages.error(request, "You cannot cancel an appointment that has already started.")
        return redirect("my_appointments")

    # Proceed with cancellation
    appt.status = "cancelled"
    appt.save()
    messages.success(request, "Appointment cancelled.")

    # Redirect to proper dashboard
    if request.user == appt.professional:
        return redirect("professional_appointments")
    else:
        return redirect("my_appointments")


@login_required
def complete_appointment(request, appointment_id):
    appt = get_object_or_404(Appointment, id=appointment_id)

    if request.user != appt.professional:
        return HttpResponseForbidden("You do not have permission to complete this appointment.")

    appt.status = "completed"
    appt.save()
    messages.success(request, "Appointment marked as completed.")

    return redirect("professional_appointments")

@login_required
def edit_appointment(request, appointment_id):
    appt = get_object_or_404(Appointment, id=appointment_id)

    # Permissions:
    # - Professional can edit if not cancelled/completed
    # - Client can edit only if appointment hasn't started yet
    from django.utils import timezone
    now = timezone.now()

    if request.user == appt.client:
        if appt.scheduled_time <= now:
            messages.error(request, "You cannot edit an appointment that has already started.")
            return redirect("my_appointments")

    elif request.user == appt.professional:
        if appt.status in ("cancelled", "completed"):
            messages.error(request, "You cannot edit a cancelled or completed appointment.")
            return redirect("professional_appointments")

    else:
        return HttpResponseForbidden("You cannot edit this appointment.")

    # Handle incoming POST changes
    if request.method == "POST":
        form = AppointmentForm(request.POST, instance=appt)
        
        # Make sure instance retains client/professional
        appt.client = appt.client
        appt.professional = appt.professional

        if form.is_valid():
            updated = form.save(commit=False)
            updated.full_clean()     # triggers overlap, business hours, duration checks
            updated.save()
            messages.success(request, "Appointment updated successfully!")

            if request.user == appt.professional:
                return redirect("professional_appointments")
            else:
                return redirect("my_appointments")

    # GET request: show form pre-filled
    else:
        form = AppointmentForm(instance=appt)

    return render(request, "appointments/edit_appointment.html", {"form": form, "appointment": appt})


