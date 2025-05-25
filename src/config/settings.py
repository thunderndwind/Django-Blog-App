from pathlib import Path
import sys
import os
from datetime import timedelta
from dotenv import load_dotenv
import dj_database_url      

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "apps"))

IS_PRODUCTION = os.getenv('DJANGO_PRODUCTION', 'False').lower() == 'true'

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'unsafe-default-key')
DEBUG = not IS_PRODUCTION

# Custom User Model
AUTH_USER_MODEL = 'users.User'

# Core URLs and Domains
RENDER_EXTERNAL_URL = os.getenv('RENDER_EXTERNAL_URL', '').rstrip('/')
NETLIFY_URL = os.getenv('NETLIFY_URL', 'https://app.netlify.app').rstrip('/')
DOMAIN = RENDER_EXTERNAL_URL.replace('https://', '') if IS_PRODUCTION else 'localhost'

ALLOWED_HOSTS = [DOMAIN, 'localhost', '127.0.0.1']

# Unified Cookie Settings for Cross-Origin
COOKIE_SETTINGS = {
    'httponly': True,
    'secure': IS_PRODUCTION,
    'samesite': 'None' if IS_PRODUCTION else 'Lax',  # Must be 'None' for cross-origin
    'domain': None,  # Don't set domain for cross-origin cookies
    'path': '/',
}

# Apply cookie settings consistently
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
}

# Session configuration
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
SESSION_COOKIE_SECURE = COOKIE_SETTINGS['secure']
SESSION_COOKIE_HTTPONLY = COOKIE_SETTINGS['httponly']
SESSION_COOKIE_SAMESITE = COOKIE_SETTINGS['samesite']
SESSION_COOKIE_DOMAIN = COOKIE_SETTINGS['domain']

# CSRF configuration - consistent with other cookies
CSRF_COOKIE_NAME = 'csrftoken'
CSRF_COOKIE_SECURE = COOKIE_SETTINGS['secure']
CSRF_COOKIE_HTTPONLY = False  # Must be False for JavaScript access
CSRF_COOKIE_SAMESITE = COOKIE_SETTINGS['samesite']  # Use same as other cookies
CSRF_COOKIE_DOMAIN = COOKIE_SETTINGS['domain']  # Use same as other cookies
CSRF_COOKIE_PATH = COOKIE_SETTINGS['path']
CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'
CSRF_USE_SESSIONS = False
CSRF_FAILURE_VIEW = 'apps.utils.responses.csrf_failure'

CSRF_TRUSTED_ORIGINS = [
    NETLIFY_URL,
    RENDER_EXTERNAL_URL,
    'http://localhost:5173',
    'http://localhost:3000',
]

# CORS configuration
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = CSRF_TRUSTED_ORIGINS  # Use same origins as CSRF
CORS_EXPOSE_HEADERS = [
    'Access-Control-Allow-Credentials',
    'Access-Control-Allow-Origin',
    'X-CSRFToken',
    'Set-Cookie',
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
    'cookie',
]

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'apps.users.authentication.CustomJWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
    'EXCEPTION_HANDLER': 'apps.utils.exceptions.custom_exception_handler',
}

# Uploadcare configuration
UPLOADCARE = {
    'pub_key': os.getenv('UPLOADCARE_PUBLIC_KEY'),
    'secret': os.getenv('UPLOADCARE_SECRET_KEY'),
    'cdn_base': 'https://ucarecdn.com',
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party apps
    'rest_framework',
    'corsheaders',
    'django_redis',
    # Custom apps     
    'apps.users',
    'apps.posts',
    'apps.uploads',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'apps.utils.security.CustomCsrfMiddleware',  # Replace default CSRF middleware
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'apps.utils.security.AutoCSRFMiddleware',  # Automatically attach CSRF tokens
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # Templates directory
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

# Security Settings for Production
if IS_PRODUCTION:
    SECURE_SSL_REDIRECT = True
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
        'apps.utils': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
