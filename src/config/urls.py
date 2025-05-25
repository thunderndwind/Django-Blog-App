"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static
from apps.users import urls as users_urls

urlpatterns = [
    path('admin-secure-web/', admin.site.urls),
    path('api/auth/', include(users_urls.auth_patterns)),  # Auth endpoints
    path('api/posts/', include('apps.posts.urls')),
    path('api/uploads/', include('apps.uploads.urls')),
    path('api/users/', include('apps.users.urls')),  # User endpoints
    # Health check endpoint for Render
    path('health/', lambda request: HttpResponse("OK")),
    # Serve index.html for root path
    path('', TemplateView.as_view(template_name='index.html')),
    # Catch all other routes
    re_path(r'^(?!api/).*$', TemplateView.as_view(template_name='index.html')),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
