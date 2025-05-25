from functools import wraps
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from apps.utils.web_detection import is_web_client
from django.middleware.csrf import get_token
import logging

logger = logging.getLogger(__name__)

def conditional_csrf_protect(view_func):
    """
    Decorator that enables CSRF protection only for web clients.
    Ensures CSRF token is available for JavaScript access.
    """
    protected_view = csrf_protect(view_func)
    exempt_view = csrf_exempt(view_func)
    
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if is_web_client(request):
            # Ensure CSRF token is generated and available
            csrf_token = get_token(request)
            logger.debug(f"CSRF protection enabled for web client, token: {csrf_token[:10]}...")
            return protected_view(request, *args, **kwargs)
        else:
            logger.debug("CSRF protection disabled for API client")
            return exempt_view(request, *args, **kwargs)
    return wrapped_view

def ensure_csrf_token(view_func):
    """
    Decorator that ensures CSRF token is available in the response for web clients
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        response = view_func(request, *args, **kwargs)
        
        # For web clients, ensure CSRF token is in response
        if is_web_client(request) and hasattr(response, 'set_cookie'):
            csrf_token = get_token(request)
            
            # Add to response headers
            response['X-CSRFToken'] = csrf_token
            
            # Add to response data if it's a DRF response
            if hasattr(response, 'data') and isinstance(response.data, dict):
                if 'data' in response.data:
                    response.data['csrfToken'] = csrf_token
                else:
                    response.data['csrfToken'] = csrf_token
            
            logger.debug(f"CSRF token added to response: {csrf_token[:10]}...")
        
        return response
    return wrapped_view
