from django.http import HttpResponseForbidden, JsonResponse
from django.middleware.csrf import CsrfViewMiddleware, get_token
from apps.utils.web_detection import is_web_client
from apps.utils.responses import error_response
from rest_framework import status
from django.conf import settings
import json

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

class AutoCSRFMiddleware:
    """
    Middleware that automatically attaches CSRF tokens to responses for web clients
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Automatically attach CSRF token for web clients
        if is_web_client(request) and hasattr(response, 'set_cookie'):
            csrf_token = get_token(request)
            response.set_cookie(
                'csrftoken',
                csrf_token,
                max_age=3600 * 24 * 7,  # 7 days
                secure=settings.COOKIE_SETTINGS['secure'],
                httponly=False,  # Must be False for JavaScript access
                samesite=settings.COOKIE_SETTINGS['samesite'],
                domain=settings.COOKIE_SETTINGS['domain'],
                path=settings.COOKIE_SETTINGS['path']
            )
            response['X-CSRFToken'] = csrf_token
        
        return response

class CustomCsrfMiddleware(CsrfViewMiddleware):
    def _reject(self, request, reason):
        # Return a proper JsonResponse instead of DRF Response
        return JsonResponse({
            'status': 'error',
            'message': 'CSRF token verification failed',
            'errors': reason
        }, status=403)

    def process_view(self, request, callback, callback_args, callback_kwargs):
        if getattr(request, '_dont_enforce_csrf_checks', False):
            return None
            
        # Skip CSRF for non-web clients
        if not is_web_client(request):
            return None
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            if csrf_token:
                request.META['HTTP_X_CSRFTOKEN'] = csrf_token
            return super().process_view(request, callback, callback_args, callback_kwargs)
        except Exception:
            return self._reject(request, "CSRF token missing or incorrect")
