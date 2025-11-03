# apps/appointments/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("book/<int:professional_id>/", views.book_appointment, name="book_appointment"),
    path("book/success/", views.booking_success, name="booking_success"),
]

