from pathlib import Path
import sys
import os
from datetime import timedelta
from dotenv import load_dotenv
import dj_database_url  # Add this import

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "apps"))

IS_PRODUCTION = os.getenv('DJANGO_PRODUCTION', 'False').lower() == 'true'

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'unsafe-default-key')
DEBUG = not IS_PRODUCTION

# Get deployment URLs
RENDER_EXTERNAL_URL = os.getenv('RENDER_EXTERNAL_URL', '').rstrip('/')
NETLIFY_URL = os.getenv('NETLIFY_URL', 'https://app.netlify.app').rstrip('/')
FRONTEND_URL = os.getenv('NETLIFY_URL', 'https://app.netlify.app').rstrip('/')
DOMAIN = RENDER_EXTERNAL_URL.replace('https://', '') if IS_PRODUCTION else 'localhost'

ALLOWED_HOSTS = [
    DOMAIN,
]

# Unified Cookie Settings
COOKIE_SETTINGS = {
    'httponly': True,
    'secure': IS_PRODUCTION,
    'samesite': 'None' if IS_PRODUCTION else 'Lax',  # Must be 'None' for cross-origin
    'domain': DOMAIN if IS_PRODUCTION else None,
    'path': '/',
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework',
    'corsheaders',

    'apps.users',
    'apps.posts',
    'apps.uploads',  # Add this line
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # Add templates directory
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

# Update DATABASE configuration for Render
if 'DATABASE_URL' in os.environ:
    DATABASES['default'] = dj_database_url.config(
        conn_max_age=600,
        conn_health_checks=True,
    )

# Cache (Redis)
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": os.getenv('REDIS_URL'),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# JWT
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'COOKIE_NAME': 'access_token',
    'COOKIE_REFRESH_NAME': 'refresh_token',
    'COOKIE_SECURE': COOKIE_SETTINGS['secure'],
    'COOKIE_HTTPONLY': COOKIE_SETTINGS['httponly'],
    'COOKIE_SAMESITE': COOKIE_SETTINGS['samesite'],
    'COOKIE_DOMAIN': COOKIE_SETTINGS['domain'],
    'COOKIE_PATH': COOKIE_SETTINGS['path'],
}

# CSRF
CSRF_COOKIE_NAME = 'csrftoken'
CSRF_COOKIE_SECURE = COOKIE_SETTINGS['secure']
CSRF_COOKIE_HTTPONLY = False  # Must be False for JavaScript access
CSRF_COOKIE_SAMESITE = COOKIE_SETTINGS['samesite']
CSRF_COOKIE_DOMAIN = COOKIE_SETTINGS['domain']
CSRF_USE_SESSIONS = False
CSRF_TRUSTED_ORIGINS = [
    NETLIFY_URL,
    FRONTEND_URL,
    'http://localhost:5173',
    'http://localhost:3000',
]

# Session Settings
SESSION_COOKIE_SECURE = COOKIE_SETTINGS['secure']
SESSION_COOKIE_HTTPONLY = COOKIE_SETTINGS['httponly']
SESSION_COOKIE_SAMESITE = COOKIE_SETTINGS['samesite']
SESSION_COOKIE_DOMAIN = COOKIE_SETTINGS['domain']

# CORS Settings for cross-origin cookies
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    NETLIFY_URL,
    FRONTEND_URL,
    'http://localhost:5173',
    'http://localhost:3000',
]
CORS_EXPOSE_HEADERS = [
    'Access-Control-Allow-Credentials',
    'Access-Control-Allow-Origin',
    'X-CSRFToken',
]
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Cookie & Domain settings
COOKIE_DOMAIN = os.getenv('COOKIE_DOMAIN', 'localhost')
SESSION_COOKIE_DOMAIN = DOMAIN if IS_PRODUCTION else None
CSRF_COOKIE_DOMAIN = DOMAIN if IS_PRODUCTION else None
SESSION_COOKIE_SECURE = IS_PRODUCTION
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict' 

# Security Settings for Production
if IS_PRODUCTION:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    X_FRAME_OPTIONS = 'DENY'


STATIC_URL= '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'apps.users': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
