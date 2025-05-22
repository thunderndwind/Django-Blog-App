from django.urls import path
from .views import UploadcarePresignedURLView

app_name = 'uploads'

urlpatterns = [
    path('presigned-url', UploadcarePresignedURLView.as_view(), name='presigned-url'),
]
