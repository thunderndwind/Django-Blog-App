from rest_framework.pagination import CursorPagination
from rest_framework.response import Response
from .responses import success_response

class CustomCursorPagination(CursorPagination):
    page_size = 10
    ordering = '-created_at'
    cursor_query_param = 'cursor'
    
    def get_paginated_response(self, data):
        return success_response(
            message='Data retrieved successfully',
            data=data,
            pagination={
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'page_size': self.page_size
            }
        )
