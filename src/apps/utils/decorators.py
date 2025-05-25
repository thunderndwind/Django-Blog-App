from functools import wraps
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from apps.utils.web_detection import is_web_client

def conditional_csrf_protect(view_func):
    """
    Decorator that enables CSRF protection only for web clients.
    """
    protected_view = csrf_protect(view_func)
    exempt_view = csrf_exempt(view_func)
    
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if is_web_client(request):
            return protected_view(request, *args, **kwargs)
        return exempt_view(request, *args, **kwargs)
    return wrapped_view
