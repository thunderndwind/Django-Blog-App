from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ValidationError
from .serializers import UserRegisterSerializer, UserLoginSerializer
from django.conf import settings
import logging
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser
from apps.utils.responses import success_response, error_response, create_response_with_csrf, get_csrf_token_for_js
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.middleware.csrf import CsrfViewMiddleware, get_token
from django.utils.decorators import method_decorator
from apps.utils.web_detection import is_web_client
from apps.utils.decorators import conditional_csrf_protect, ensure_csrf_token
import re
from django.middleware.csrf import get_token
from django.http import JsonResponse

logger = logging.getLogger(__name__)

@method_decorator(conditional_csrf_protect, name='dispatch')
@method_decorator(ensure_csrf_token, name='dispatch')
class RegisterView(APIView):
    permission_classes = [AllowAny]
    parser_classes = (JSONParser,)

    def post(self, request):
        try:
            if not request.content_type == 'application/json':
                return error_response('Content-Type must be application/json')

            logger.info(f"Registration attempt with data: {request.data}")
            
            serializer = UserRegisterSerializer(data=request.data)
            
            if not serializer.is_valid():
                return error_response('Validation failed', serializer.errors)
            
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            
            response_data = {
                'user': serializer.data,
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }
            }
            
            if is_web_client(request):
                # Use the new response function that includes CSRF token
                response = create_response_with_csrf(
                    'Registration successful',
                    response_data,
                    status.HTTP_201_CREATED,
                    request=request
                )
                
                # Set auth token for web clients
                response.set_cookie(
                    settings.SIMPLE_JWT['COOKIE_NAME'],
                    str(refresh.access_token),
                    max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
                    secure=settings.SIMPLE_JWT['COOKIE_SECURE'],
                    httponly=settings.SIMPLE_JWT['COOKIE_HTTPONLY'],
                    samesite=settings.SIMPLE_JWT['COOKIE_SAMESITE'],
                    domain=settings.SIMPLE_JWT['COOKIE_DOMAIN'],
                    path=settings.COOKIE_SETTINGS['path']
                )
            else:
                response = success_response(
                    'Registration successful',
                    response_data,
                    status.HTTP_201_CREATED
                )
            
            return response
                
        except ParseError as e:
            return error_response('Invalid JSON format', str(e))
        except ValidationError as e:
            return error_response('Validation error', str(e))
        except Exception as e:
            logger.info(f"Registration error: {str(e)}")
            return error_response(
                'Registration failed',
                str(e) if settings.DEBUG else 'Internal server error',
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(conditional_csrf_protect, name='dispatch')
@method_decorator(ensure_csrf_token, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]
    parser_classes = (JSONParser,)

    def post(self, request):
        try:
            logger.info(f"Login attempt from {request.headers.get('Origin', 'Unknown')} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
            logger.info(f"Is web client: {is_web_client(request)}")
            logger.info(f"CSRF token in headers: {request.headers.get('X-CSRF-Token', 'None')}")
            logger.info(f"CSRF token in cookies: {request.COOKIES.get('csrftoken', 'None')}")
            
            if not request.content_type == 'application/json':
                return error_response('Content-Type must be application/json')

            serializer = UserLoginSerializer(data=request.data)
            if not serializer.is_valid():
                return error_response('Validation failed', serializer.errors)

            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                refresh = RefreshToken.for_user(user)
                response_data = {
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'profile_picture': user.profile_picture_url,
                        'bio': user.bio or '',
                        'birth_date': user.birth_date
                    }
                }

                if is_web_client(request):
                    # Use the new response function that includes CSRF token
                    response = create_response_with_csrf('Login successful', response_data, request=request)
                    
                    # Set auth tokens with consistent settings
                    logger.info(f"Setting cookies for web client - secure: {settings.SIMPLE_JWT['COOKIE_SECURE']}, samesite: {settings.SIMPLE_JWT['COOKIE_SAMESITE']}, domain: {settings.SIMPLE_JWT['COOKIE_DOMAIN']}")
                    
                    response.set_cookie(
                        settings.SIMPLE_JWT['COOKIE_NAME'],
                        str(refresh.access_token),
                        max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
                        secure=settings.SIMPLE_JWT['COOKIE_SECURE'],
                        httponly=settings.SIMPLE_JWT['COOKIE_HTTPONLY'],
                        samesite=settings.SIMPLE_JWT['COOKIE_SAMESITE'],
                        domain=settings.SIMPLE_JWT['COOKIE_DOMAIN'],
                        path=settings.COOKIE_SETTINGS['path']
                    )
                    response.set_cookie(
                        settings.SIMPLE_JWT['COOKIE_REFRESH_NAME'],
                        str(refresh),
                        max_age=int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()),
                        secure=settings.SIMPLE_JWT['COOKIE_SECURE'],
                        httponly=settings.SIMPLE_JWT['COOKIE_HTTPONLY'],
                        samesite=settings.SIMPLE_JWT['COOKIE_SAMESITE'],
                        domain=settings.SIMPLE_JWT['COOKIE_DOMAIN'],
                        path=settings.COOKIE_SETTINGS['path']
                    )
                    
                    logger.info("Cookies set successfully for web client")
                else:
                    # Return tokens in response for non-web clients
                    response_data['tokens'] = {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh)
                    }
                    response = success_response('Login successful', response_data)
                
                return response
                    
            return error_response(
                'Invalid credentials',
                status_code=status.HTTP_401_UNAUTHORIZED
            )
            
        except ParseError as e:
            return error_response('Invalid JSON format', str(e))
        except Exception as e:
            return error_response(
                'Login failed',
                str(e) if settings.DEBUG else 'Internal server error',
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(conditional_csrf_protect, name='dispatch')
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Try to blacklist the refresh token if available
            refresh_token = None
            is_web = is_web_client(request)
            
            if is_web:
                refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['COOKIE_REFRESH_NAME'])
            else:
                refresh_token = request.data.get('refresh')
            
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    logger.info("Refresh token blacklisted successfully")
                except Exception as e:
                    logger.warning(f"Failed to blacklist refresh token: {str(e)}")
            
            response = success_response('Logged out successfully')
            
            # For cross-origin cookie deletion, we need to set cookies with the same attributes
            # and expire them, rather than using delete_cookie which doesn't work reliably
            
            # Clear JWT access token cookie
            response.set_cookie(
                settings.SIMPLE_JWT['COOKIE_NAME'],
                '',  # Empty value
                max_age=0,  # Expire immediately
                expires='Thu, 01 Jan 1970 00:00:00 GMT',  # Past date
                path=settings.COOKIE_SETTINGS['path'],
                domain=settings.SIMPLE_JWT['COOKIE_DOMAIN'],
                secure=settings.SIMPLE_JWT['COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['COOKIE_HTTPONLY'],
                samesite=settings.SIMPLE_JWT['COOKIE_SAMESITE']
            )
            
            # Clear JWT refresh token cookie
            response.set_cookie(
                settings.SIMPLE_JWT['COOKIE_REFRESH_NAME'],
                '',  # Empty value
                max_age=0,  # Expire immediately
                expires='Thu, 01 Jan 1970 00:00:00 GMT',  # Past date
                path=settings.COOKIE_SETTINGS['path'],
                domain=settings.SIMPLE_JWT['COOKIE_DOMAIN'],
                secure=settings.SIMPLE_JWT['COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['COOKIE_HTTPONLY'],
                samesite=settings.SIMPLE_JWT['COOKIE_SAMESITE']
            )
            
            # Clear CSRF token cookie
            response.set_cookie(
                'csrftoken',
                '',  # Empty value
                max_age=0,  # Expire immediately
                expires='Thu, 01 Jan 1970 00:00:00 GMT',  # Past date
                path=settings.CSRF_COOKIE_PATH,
                domain=settings.CSRF_COOKIE_DOMAIN,
                secure=settings.CSRF_COOKIE_SECURE,
                httponly=settings.CSRF_COOKIE_HTTPONLY,
                samesite=settings.CSRF_COOKIE_SAMESITE
            )
            
            logger.info("Logout: Successfully cleared all authentication and CSRF cookies")
            return response
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return error_response('Logout failed', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(conditional_csrf_protect, name='dispatch')
@method_decorator(ensure_csrf_token, name='dispatch')
class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'profile_picture': user.profile_picture_url,
                'bio': user.bio or '',
                'birth_date': user.birth_date
            }
            
            if is_web_client(request):
                response = create_response_with_csrf('User details retrieved successfully', data, request=request)
            else:
                response = success_response('User details retrieved successfully', data)
            
            return response
        except Exception as e:
            return error_response('Failed to retrieve user details', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

class TokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Try to get refresh token from cookies first for web clients
            is_web = is_web_client(request)
            if is_web:
                refresh_token = request.COOKIES.get('refresh_token')
            else:
                refresh_token = request.data.get('refresh')
            
            if not refresh_token:
                return error_response('Refresh token is required', status_code=status.HTTP_400_BAD_REQUEST)

            try:
                refresh = RefreshToken(refresh_token)
                response_data = {}
                
                if is_web:
                    response = success_response('Token refreshed successfully', response_data)
                    response.set_cookie(
                        settings.SIMPLE_JWT['COOKIE_NAME'],
                        str(refresh.access_token),
                        max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
                        secure=settings.SIMPLE_JWT['COOKIE_SECURE'],
                        httponly=settings.SIMPLE_JWT['COOKIE_HTTPONLY'],
                        samesite=settings.SIMPLE_JWT['COOKIE_SAMESITE'],
                        domain=settings.SIMPLE_JWT['COOKIE_DOMAIN'],
                        path=settings.COOKIE_SETTINGS['path']
                    )
                else:
                    response_data['tokens'] = {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh)
                    }
                    response = success_response('Token refreshed successfully', response_data)
                
                return response

            except TokenError:
                return error_response('Invalid refresh token', status_code=status.HTTP_401_UNAUTHORIZED)
            
        except Exception as e:
            return error_response('Token refresh failed', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

class TokenVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = request.data.get('token') or request.COOKIES.get(settings.SIMPLE_JWT['COOKIE_NAME'])
            if not token:
                return error_response('Token is required', status_code=status.HTTP_400_BAD_REQUEST)

            try:
                UntypedToken(token)
                return success_response('Token is valid')
            except (InvalidToken, TokenError):
                return error_response('Token is invalid or expired', status_code=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return error_response('Token verification failed', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            stats = {
                'posts_count': user.posts.count(),
                'followers_count': user.followers.count(),
                'following_count': user.following.count(),
                'likes_given': user.liked_posts.count(),
                'likes_received': sum(post.likes.count() for post in user.posts.all())
            }
            
            data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'bio': user.bio,
                'birth_date': user.birth_date,
                'profile_picture': user.profile_picture_url,
                'stats': stats
            }
            return success_response('Profile retrieved successfully', data)
        except Exception as e:
            return error_response('Failed to retrieve profile', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request):
        try:
            user = request.user
            allowed_fields = ['first_name', 'last_name', 'bio', 'birth_date', 'profile_picture']
            
            for field in allowed_fields:
                if field in request.data:
                    # Handle profile picture separately
                    if field == 'profile_picture':
                        value = request.data[field]
                        if not value:  # Handle empty value
                            continue
                            
                        # Validate UUID or CDN URL
                        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                        value = str(value).strip('/')
                        
                        # Direct UUID
                        if re.match(uuid_pattern, value):
                            setattr(user, field, value)
                            continue
                            
                        # CDN URL
                        if 'ucarecdn.com' in value:
                            uuid = value.split('ucarecdn.com/')[-1].strip('/')
                            if re.match(uuid_pattern, uuid):
                                setattr(user, field, uuid)
                                continue
                                
                        raise ValidationError('Invalid profile picture format')
                    else:
                        setattr(user, field, request.data[field])
            
            user.save()
            return success_response('Profile updated successfully', {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'bio': user.bio,
                'birth_date': user.birth_date,
                'profile_picture': user.profile_picture_url
            })
        except ValidationError as e:
            return error_response('Validation error', str(e), status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return error_response('Failed to update profile', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

class CSRFTokenView(APIView):
    """
    Endpoint to get CSRF token for authenticated requests
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        if is_web_client(request):
            csrf_token = get_csrf_token_for_js(request)
            response = success_response('CSRF token retrieved', {'csrfToken': csrf_token})
            
            # Set CSRF token in cookie
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
            
            # Also include in response header
            response['X-CSRFToken'] = csrf_token
            
            logger.info(f"CSRF token provided to web client: {csrf_token[:10]}...")
            return response
        else:
            return success_response('CSRF token not required for API clients', {'csrfToken': None})
