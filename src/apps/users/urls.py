from django.urls import path
from .views import RegisterView, LoginView, TokenRefreshView, TokenVerifyView, LogoutView, MeView, UserProfileView

app_name = 'users'

urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('login', LoginView.as_view(), name='login'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify', TokenVerifyView.as_view(), name='token_verify'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('me', MeView.as_view(), name='me'),
    path('profile', UserProfileView.as_view(), name='profile'),
]
