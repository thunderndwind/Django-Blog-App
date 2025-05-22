from django.urls import path
from .views import (
    PostListCreateView, PostDetailView, 
    PostLikeView, UploadcarePresignedURLView
)

app_name = 'posts'

urlpatterns = [
    path('', PostListCreateView.as_view(), name='post-list-create'),
    path('<int:pk>', PostDetailView.as_view(), name='post-detail'),
    path('<int:pk>/like', PostLikeView.as_view(), name='post-like'),
    path('upload/presigned-url', UploadcarePresignedURLView.as_view(), name='presigned-url'),
]
