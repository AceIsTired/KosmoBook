class InitializedUserCheck:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only check authenticated users
        if request.user.is_authenticated:
            # Don't redirect if already on initialization page or logging out
            if (not request.user.is_initialized and
                not request.path.startswith('/auth/initialize/') and
                not request.path.startswith('/accounts/setup/') and
                not request.path.startswith('/auth/logout/') and
                not request.path.startswith('/admin/')):
                from django.shortcuts import redirect
                return redirect('setup_profile')

        return self.get_response(request)