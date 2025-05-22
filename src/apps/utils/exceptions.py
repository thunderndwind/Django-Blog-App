from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework import status
from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException, ValidationError
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from .responses import error_response

def custom_exception_handler(exc, context):
    """
    Custom exception handler for Django REST Framework
    that standardizes error responses.
    """
    if isinstance(exc, Http404):
        return error_response(
            message="Resource not found",
            status_code=status.HTTP_404_NOT_FOUND
        )

    if isinstance(exc, PermissionDenied):
        return error_response(
            message="Permission denied",
            status_code=status.HTTP_403_FORBIDDEN
        )

    if isinstance(exc, DjangoValidationError):
        return error_response(
            message="Validation error",
            errors=exc.message_dict if hasattr(exc, 'message_dict') else str(exc),
            status_code=status.HTTP_400_BAD_REQUEST
        )

    if isinstance(exc, ValidationError):
        return error_response(
            message="Validation error",
            errors=exc.detail,
            status_code=status.HTTP_400_BAD_REQUEST
        )

    if isinstance(exc, IntegrityError):
        return error_response(
            message="Database integrity error",
            errors=str(exc),
            status_code=status.HTTP_400_BAD_REQUEST
        )

    if isinstance(exc, APIException):
        return error_response(
            message=str(exc.detail),
            status_code=exc.status_code
        )

    # If we don't have a specific handler, let DRF handle it
    # or provide a generic error response
    response = exception_handler(exc, context)
    
    if response is not None:
        return error_response(
            message="An error occurred",
            errors=response.data,
            status_code=response.status_code
        )

    # Catch any other exceptions
    return error_response(
        message="Internal server error",
        errors=str(exc) if context.get('request').META.get('DEBUG', False) else None,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )
