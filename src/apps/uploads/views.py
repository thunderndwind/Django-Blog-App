from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from apps.utils.responses import success_response, error_response
from rest_framework import status
import time
import hmac
import hashlib
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class UploadcarePresignedURLView(APIView):
    permission_classes = [IsAuthenticated]

    def generate_secure_signature(self, secret, expire):
        k, m = secret, str(expire).encode('utf-8')
        if not isinstance(k, (bytes, bytearray)):
            k = k.encode('utf-8')
        return hmac.new(k, m, hashlib.sha256).hexdigest()

    def get(self, request):
        try:
            expire = int(time.time()) + 3600
            signature = self.generate_secure_signature(
                settings.UPLOADCARE['secret'],
                expire
            )
            
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
