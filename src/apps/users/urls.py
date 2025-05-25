from django.urls import path, include
from .views import (
    RegisterView, LoginView, TokenRefreshView, 
    TokenVerifyView, LogoutView, MeView, UserProfileView, CSRFTokenView
)

app_name = 'users'

auth_patterns = [
    path('csrf-token', CSRFTokenView.as_view(), name='csrf_token'),
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
