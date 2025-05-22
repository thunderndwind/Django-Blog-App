from django.http import HttpResponseForbidden
from django.middleware.csrf import CsrfViewMiddleware
from apps.utils.web_detection import is_web_client

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

class ConditionalCSRFMiddleware(CsrfViewMiddleware):
    def process_view(self, request, callback, callback_args, callback_kwargs):
        if is_web_client(request):
            return super().process_view(request, callback, callback_args, callback_kwargs)
        return None

    def process_response(self, request, response):
        if is_web_client(request):
            return super().process_response(request, response)
        return response
