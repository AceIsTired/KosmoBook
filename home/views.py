from django.shortcuts import render

def home_page(request):
    """Main home page view"""
    context = {
        'title': 'Welcome to Kosmos',
        'message': 'Your cosmic journey begins here!'
    }
    return render(request, 'home/home.html', context)

def about_page(request):
    """About page view"""
    return render(request, 'home/about.html')

def contact_page(request):
    """Contact page view"""
    return render(request, 'home/contact.html')
