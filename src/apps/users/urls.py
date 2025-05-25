from django.urls import path, include
from .views import (
    RegisterView, LoginView, TokenRefreshView, 
    TokenVerifyView, LogoutView, MeView, UserProfileView, GetCSRFTokenView
)

app_name = 'users'

auth_patterns = [
    path('csrf-token', GetCSRFTokenView.as_view(), name='get_csrf_token'),
    path('register', RegisterView.as_view(), name='register'),
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify', TokenVerifyView.as_view(), name='token_verify'),
]

user_patterns = [
    path('me', MeView.as_view(), name='me'),
    path('profile', UserProfileView.as_view(), name='profile'),
]

urlpatterns = user_patterns
