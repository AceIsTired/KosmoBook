from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

# Customize how CustomUser appears in admin
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'date_of_birth', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active')
    fieldsets = UserAdmin.fieldsets + (
        ('Additional Info', {'fields': ('date_of_birth', 'bio', 'profile_picture')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Additional Info', {'fields': ('email', 'date_of_birth')}),
    )

# Register your models
admin.site.register(CustomUser, CustomUserAdmin)
