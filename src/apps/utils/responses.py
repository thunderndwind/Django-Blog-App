from rest_framework.response import Response
from rest_framework import status
from django.middleware.csrf import get_token
from django.conf import settings
from .web_detection import is_web_client

def success_response(message, data=None, status_code=status.HTTP_200_OK, pagination=None):
    response_data = {
        'status': 'success',
        'message': message,
    }
    if data is not None:
        response_data.update({'data': data})
    if pagination is not None:
        response_data.update({'pagination': pagination})
    return Response(response_data, status=status_code)

def error_response(message, errors=None, status_code=status.HTTP_400_BAD_REQUEST):
    response_data = {
        'status': 'error',
        'message': message,
    }
    if errors is not None:
        response_data.update({'errors': errors})
    return Response(response_data, status=status_code)

def csrf_failure(request, reason=""):
    return error_response(
        message="CSRF verification failed",
        errors=reason,
        status_code=status.HTTP_403_FORBIDDEN
    )

def get_csrf_token_for_js(request):
    """
    Get CSRF token and ensure it's accessible for JavaScript
    """
    csrf_token = get_token(request)
    return csrf_token

def attach_csrf_cookie(response, request):
    """
    Automatically attach CSRF token to response cookies for web clients
    """
    if is_web_client(request):
        csrf_token = get_token(request)
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
    return response

def create_response_with_csrf(message, data=None, status_code=status.HTTP_200_OK, request=None):
    """
    Create a success response and automatically attach CSRF token for web clients
    """
    response = success_response(message, data, status_code)
    if request and is_web_client(request):
        csrf_token = get_csrf_token_for_js(request)
        # Add CSRF token to response data for JS access
        if isinstance(response.data, dict) and 'data' in response.data:
            response.data['csrfToken'] = csrf_token
        # Also set it in cookie for automatic inclusion
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
    return response
