# apps/appointments/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("book/<int:professional_id>/", views.book_appointment, name="book_appointment"),
    path("book/success/", views.booking_success, name="booking_success"),

    #path for professional dashboard 
    path("professional/appointments/",views.professional_appointments,name="professional_appointments",),

    #path for customer appointments 
    path("my-appointments/",views.my_appointments,name="my_appointments"),

    #path to confirm, cancel, and complete appointment 
    path("appointment/<int:appointment_id>/confirm/", views.confirm_appointment, name="confirm_appointment"),
    path("appointment/<int:appointment_id>/cancel/", views.cancel_appointment, name="cancel_appointment"),
    path("appointment/<int:appointment_id>/complete/", views.complete_appointment, name="complete_appointment"),

    path("appointment/<int:appointment_id>/edit/",views.edit_appointment,name="edit_appointment"),



]

