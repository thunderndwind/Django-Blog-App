from django.http import HttpResponseForbidden, JsonResponse
from django.middleware.csrf import CsrfViewMiddleware, get_token
from apps.utils.web_detection import is_web_client
from apps.utils.responses import error_response
from rest_framework import status
from django.conf import settings
from rest_framework.response import Response
import json
import logging

logger = logging.getLogger(__name__)

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
        is_web = is_web_client(request)
        if is_web and hasattr(response, 'set_cookie'):
            csrf_token = get_token(request)
            logger.info(f"AutoCSRF: Attaching CSRF token to response for {request.path}")
            response.set_cookie(
                'csrftoken',
                csrf_token,
                max_age=3600 * 24 * 7,  # 7 days
                secure=settings.CSRF_COOKIE_SECURE,
                httponly=settings.CSRF_COOKIE_HTTPONLY,
                samesite=settings.CSRF_COOKIE_SAMESITE,
                domain=settings.CSRF_COOKIE_DOMAIN,
                path=settings.CSRF_COOKIE_PATH
            )
            response['X-CSRFToken'] = csrf_token
        elif is_web:
            logger.info(f"AutoCSRF: Web client detected but response doesn't support cookies for {request.path}")
        else:
            logger.info(f"AutoCSRF: Non-web client, skipping CSRF token for {request.path}")
        
        return response

class CustomCsrfMiddleware(CsrfViewMiddleware):
    def _reject(self, request, reason):
        # Return a proper JsonResponse for CSRF failures
        response = JsonResponse({
            'status': 'error',
            'message': 'CSRF token verification failed',
            'errors': reason
        }, status=403)
        response['Content-Type'] = 'application/json'
        return response

    def process_view(self, request, callback, callback_args, callback_kwargs):
        if getattr(request, '_dont_enforce_csrf_checks', False):
            return None
            
        # Skip CSRF for non-web clients
        is_web = is_web_client(request)
        logger.info(f"CSRF check - is_web_client: {is_web}, path: {request.path}, origin: {request.headers.get('Origin', 'None')}")
        
        if not is_web:
            logger.info("Skipping CSRF for non-web client")
            return None
            
        # For web clients, check for CSRF token in multiple places
        csrf_token = None
        
        # 1. Check X-CSRF-Token header (preferred method for JS)
        csrf_token = request.headers.get('X-CSRF-Token') or request.headers.get('X-CSRFToken')
        
        # 2. Check standard Django CSRF header
        if not csrf_token:
            csrf_token = request.META.get('HTTP_X_CSRFTOKEN')
        
        # 3. Check cookies as fallback
        if not csrf_token:
            csrf_token = request.COOKIES.get('csrftoken')
        
        logger.info(f"CSRF token found: {csrf_token[:10] if csrf_token else 'None'}")
        
        # Set the token in META for Django's CSRF middleware
        if csrf_token:
            request.META['HTTP_X_CSRFTOKEN'] = csrf_token
            logger.info("CSRF token set in request META")
        else:
            logger.warning("No CSRF token found in headers or cookies")
        
        try:
            return super().process_view(request, callback, callback_args, callback_kwargs)
        except Exception as e:
            logger.error(f"CSRF token validation failed: {str(e)}")
            return self._reject(request, f"CSRF token validation failed: {str(e)}")
