from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from .forms import AppointmentForm
from django.core.exceptions import ValidationError
from .models import Appointment
from django.http import HttpResponseForbidden



User = get_user_model()

@login_required
def book_appointment(request, professional_id):
    professional = get_object_or_404(User, id=professional_id)
    
    if request.method == "POST":
        form = AppointmentForm(request.POST)
        
        if form.is_valid():
            # Create appointment instance but don't save yet
            appt = form.save(commit=False)
            appt.professional = professional
            appt.client = request.user
            appt.status = 'pending'
            
            try:
                # Run model validation
                appt.full_clean()
                # If validation passes, save
                appt.save()
                messages.success(request, "Appointment booked successfully!")
                return redirect("appointments:booking_success")
                
            except ValidationError as e:
                # Add validation errors to the form for display
                # The error_dict contains field-specific errors
                if hasattr(e, 'error_dict'):
                    for field, errors in e.error_dict.items():
                        for error in errors:
                            if field == '__all__':
                                # Non-field errors
                                form.add_error(None, error.message)
                            else:
                                # Field-specific errors
                                form.add_error(field, error.message)
                else:
                    # Non-field errors
                    for error in e.messages:
                        form.add_error(None, error)
                        
                # Re-render form with errors
                return render(request, "appointments/book.html", {
                    "form": form,
                    "professional": professional,
                    "business_hours": "9:00 AM - 5:00 PM",
                })
        else:
            # Form validation errors (field-level)
            messages.error(request, "Please correct the errors below.")
    
    else:
        form = AppointmentForm()
    
    return render(request, "appointments/book.html", {
        "form": form,
        "professional": professional,
        "business_hours": "9:00 AM - 5:00 PM",
    })

def booking_success(request):
    return render(request, "appointments/success.html")

# these were the original views and were combined into appointments_dashboard
# they're here for backwards compatibility and so i dont have to go in and redefine
#all the urls in the code
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
        "is_technician": True,  # Add this flag for templates
    }
    return render(request, "appointments/professional_appointments.html", context)


@login_required
def my_appointments(request):
    """
    Unified appointments page that shows different dashboards based on user role.
    - For technicians: Show their professional appointments dashboard
    - For regular users: Show their client appointments
    """
    if request.user.is_technician:
        # Redirect technicians to their professional dashboard
        return professional_appointments(request)
    
    # For regular users, show their client appointments
    qs = Appointment.objects.filter(client=request.user).order_by("scheduled_time")

    now = timezone.now()
    upcoming_appointments = qs.filter(scheduled_time__gte=now)
    past_appointments = qs.filter(scheduled_time__lt=now)

    context = {
        "upcoming_appointments": upcoming_appointments,
        "past_appointments": past_appointments,
        "is_technician": False,  # Add this flag for templates
    }
    return render(request, "appointments/my_appointments.html", context)

@login_required
def appointments_dashboard(request):
    """
    Unified dashboard for both clients and technicians
    """
    now = timezone.now()
    
    if request.user.is_technician:
        # For technicians: show appointments where they are the professional
        qs = Appointment.objects.filter(professional=request.user)
    else:
        # For clients: show appointments where they are the client
        qs = Appointment.objects.filter(client=request.user)
    
    # Order by upcoming first
    qs = qs.order_by("scheduled_time")
    
    # Split into upcoming and past
    upcoming_appointments = qs.filter(scheduled_time__gte=now)
    past_appointments = qs.filter(scheduled_time__lt=now)
    
    # Pre-calculate the counts needed for the template
    context = {
        "upcoming_appointments": upcoming_appointments,
        "past_appointments": past_appointments,
    }
    
    # Add statistics for the dashboard cards
    if request.user.is_technician:
        # For technicians
        context["pending_count"] = upcoming_appointments.filter(status='pending').count()
        context["confirmed_count"] = upcoming_appointments.filter(status='confirmed').count()
    else:
        # For clients
        context["confirmed_count"] = upcoming_appointments.filter(status='confirmed').count()
    
    return render(request, "appointments/dashboard.html", context)


@login_required
def confirm_appointment(request, appointment_id):
    appt = get_object_or_404(Appointment, id=appointment_id)

    # Only the professional can confirm
    if request.user != appt.professional:
        return HttpResponseForbidden("You do not have permission to confirm this appointment.")

    appt.status = "confirmed"
    appt.save()
    messages.success(request, "Appointment confirmed!")
    return redirect("appointments:professional_appointments")


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
        return redirect("appointments:my_appointments")

    # Proceed with cancellation
    appt.status = "cancelled"
    appt.save()
    messages.success(request, "Appointment cancelled.")

    # Redirect to proper dashboard
    if request.user == appt.professional:
        return redirect("appointments:dashboard")
    else:
        return redirect("appointments:my_appointments")


@login_required
def complete_appointment(request, appointment_id):
    appt = get_object_or_404(Appointment, id=appointment_id)

    if request.user != appt.professional:
        return HttpResponseForbidden("You do not have permission to complete this appointment.")

    appt.status = "completed"
    appt.save()
    messages.success(request, "Appointment marked as completed.")

    return redirect("appointments:professional_appointments")

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
            return redirect("appointments:my_appointments")

    elif request.user == appt.professional:
        if appt.status in ("cancelled", "completed"):
            messages.error(request, "You cannot edit a cancelled or completed appointment.")
            return redirect("appointments:professional_appointments")

    else:
        return HttpResponseForbidden("You cannot edit this appointment.")

    # Handle incoming POST changes
    if request.method == "POST":
        form = AppointmentForm(request.POST, instance=appt)

        if form.is_valid():
            updated = form.save(commit=False)
            updated.full_clean()  # run overlap/business rules
            updated.save()

            messages.success(request, "Appointment updated successfully!")

            if request.user == appt.professional:
                return redirect("appointments:professional_appointments")
            else:
                return redirect("appointments:my_appointments")


    # GET request: show form pre-filled
    else:
        form = AppointmentForm(instance=appt)

    return render(request, "appointments/edit_appointment.html", {"form": form, "appointment": appt})