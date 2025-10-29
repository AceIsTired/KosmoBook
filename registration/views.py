from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .forms import UserRegisterForm
import json

# Create your views here.

def register(request):
    if request.method == "POST":
        data = json.loads(request.body)
        form = UserRegisterForm(data)
        if form.is_valid():
            user = form.save()
            return JsonResponse({"success": True, "message": "Account created"}, status=201)
        else:
            return JsonResponse({"success": False, "errors": form.errors}, status=400)
        
    return JsonResponse({"detail": "Method not allowed"}, status=405)
    

            

