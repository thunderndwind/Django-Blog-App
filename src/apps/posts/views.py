from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import JSONParser
from .serializers import PostSerializer
from .models import Post
from apps.utils.responses import success_response, error_response
from django.shortcuts import get_object_or_404
from django.conf import settings
import logging
from apps.utils.pagination import CustomCursorPagination
import time
import hashlib
import hmac
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from apps.utils.decorators import conditional_csrf_protect

logger = logging.getLogger(__name__)

@method_decorator(conditional_csrf_protect, name='dispatch')
class PostListCreateView(APIView):
    pagination_class = CustomCursorPagination

    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]

    parser_classes = [JSONParser]

    def get(self, request):
        try:
            posts = Post.objects.select_related('author').prefetch_related('likes').all()
            
            # Initialize paginator
            paginator = self.pagination_class()
            paginated_posts = paginator.paginate_queryset(posts, request)
            
            serializer = PostSerializer(paginated_posts, many=True)
            return paginator.get_paginated_response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error retrieving posts: {str(e)}")
            return error_response('Failed to retrieve posts', status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            serializer = PostSerializer(data=request.data)
            if not serializer.is_valid():
                return error_response('Validation failed', serializer.errors)

            serializer.save(author=request.user)
            return success_response('Post created successfully', serializer.data, status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error creating post: {str(e)}")
            return error_response('Failed to create post', status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(conditional_csrf_protect, name='dispatch')
class PostDetailView(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]

    parser_classes = [JSONParser]

    def get(self, request, pk):
        try:
            post = get_object_or_404(Post, pk=pk)
            serializer = PostSerializer(post)
            return success_response('Post retrieved successfully', serializer.data)
        except Post.DoesNotExist:
            return error_response('Post not found', status_code=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error retrieving post: {str(e)}")
            return error_response('Failed to retrieve post', status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request, pk):
        try:
            post = get_object_or_404(Post, pk=pk)
            if post.author != request.user:
                return error_response('Not authorized to update this post', status_code=status.HTTP_403_FORBIDDEN)
            
            serializer = PostSerializer(post, data=request.data, partial=True)
            if not serializer.is_valid():
                return error_response('Validation failed', serializer.errors)
                
            serializer.save()
            return success_response('Post updated successfully', serializer.data)
        except Exception as e:
            return error_response('Failed to update post', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            post = get_object_or_404(Post, pk=pk)
            if post.author != request.user:
                return error_response('Not authorized to delete this post', status_code=status.HTTP_403_FORBIDDEN)
                
            post.delete()
            return success_response('Post deleted successfully')
        except Exception as e:
            return error_response('Failed to delete post', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

class UploadcarePresignedURLView(APIView):
    permission_classes = [IsAuthenticated]

    def generate_secure_signature(self, secret, expire):
        k, m = secret, str(expire).encode('utf-8')
        if not isinstance(k, (bytes, bytearray)):
            k = k.encode('utf-8')
        return hmac.new(k, m, hashlib.sha256).hexdigest()

    def get(self, request):
        try:
            expire = int(time.time()) + 3600  # 1 hour expiration
            signature = self.generate_secure_signature(
                settings.UPLOADCARE['secret'],
                expire
            )
            print('cdn_base', settings.UPLOADCARE.get('cdn_base', 'https://ucarecdn.co'))
            print(settings.UPLOADCARE)
            # Generate the upload configuration
            response_data = {
                'pub_key': settings.UPLOADCARE['pub_key'],
                'expire': expire,
                'signature': signature,
                'secure': True,
                'image_info': True,
                'source': 'local',
                'cdn_base': settings.UPLOADCARE.get('cdn_base', 'https://ucarecdn.com')
            }
            
            return success_response('Upload configuration generated successfully', response_data)
        except Exception as e:
            logger.error(f"Error generating upload configuration: {str(e)}", exc_info=True)
            return error_response('Failed to generate upload configuration', status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(conditional_csrf_protect, name='dispatch')
class PostLikeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            post = get_object_or_404(Post, pk=pk)
            if request.user in post.likes.all():
                post.likes.remove(request.user)
                message = 'Post unliked successfully'
            else:
                post.likes.add(request.user)
                message = 'Post liked successfully'
            
            serializer = PostSerializer(post)
            return success_response(message, serializer.data)
        except Post.DoesNotExist:
            return error_response('Post not found', status_code=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error liking/unliking post: {str(e)}")
            return error_response('Failed to like/unlike post', status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
