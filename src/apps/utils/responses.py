from rest_framework.response import Response
from rest_framework import status

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
