from django.http import HttpResponseForbidden
from django.middleware.csrf import CsrfViewMiddleware
from apps.utils.web_detection import is_web_client
from apps.utils.responses import error_response
from rest_framework import status

class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response['Cache-Control'] = 'no-store, must-revalidate'
        response['Pragma'] = 'no-cache'
        
        return response

class CustomCsrfMiddleware(CsrfViewMiddleware):
    def _reject(self, request, reason):
        return error_response(
            message="CSRF token verification failed",
            errors=reason,
            status_code=status.HTTP_403_FORBIDDEN
        )

    def process_view(self, request, callback, callback_args, callback_kwargs):
        if getattr(request, '_dont_enforce_csrf_checks', False):
            return None
            
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            if csrf_token:
                request.META['HTTP_X_CSRFTOKEN'] = csrf_token
            return super().process_view(request, callback, callback_args, callback_kwargs)
        except Exception:
            return self._reject(request, "CSRF token missing or incorrect")
