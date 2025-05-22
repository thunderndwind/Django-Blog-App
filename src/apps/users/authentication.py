from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from apps.utils.web_detection import is_web_client

class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        if is_web_client(request):
            token = request.COOKIES.get('access_token')
        else:
            # Try header authentication for non-web clients
            header = self.get_header(request)
            if header is None:
                return None
            
            raw_token = self.get_raw_token(header)
            if raw_token is None:
                return None
            
            token = raw_token.decode()

        if not token:
            return None
            
        validated_token = self.get_validated_token(token)
        return self.get_user(validated_token), validated_token
