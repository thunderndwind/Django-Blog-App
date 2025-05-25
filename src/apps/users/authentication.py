from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from apps.utils.web_detection import is_web_client
import logging

logger = logging.getLogger(__name__)

class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        if is_web_client(request):
            # For web clients, try to get token from cookies
            token = request.COOKIES.get(settings.SIMPLE_JWT['COOKIE_NAME'])
            logger.debug(f"Web client token from cookie: {token[:10] if token else 'None'}")
        else:
            # Try header authentication for non-web clients
            header = self.get_header(request)
            if header is None:
                return None
            
            raw_token = self.get_raw_token(header)
            if raw_token is None:
                return None
            
            token = raw_token.decode()
            logger.debug(f"API client token from header: {token[:10] if token else 'None'}")

        if not token:
            return None
            
        try:
            validated_token = self.get_validated_token(token)
            return self.get_user(validated_token), validated_token
        except Exception as e:
            logger.debug(f"Token validation failed: {str(e)}")
            return None
