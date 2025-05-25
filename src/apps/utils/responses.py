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
            secure=settings.COOKIE_SETTINGS['secure'],
            httponly=False,  # Must be False for JavaScript access
            samesite=settings.COOKIE_SETTINGS['samesite'],
            domain=settings.COOKIE_SETTINGS['domain'],
            path=settings.COOKIE_SETTINGS['path']
        )
        response['X-CSRFToken'] = csrf_token
    return response
