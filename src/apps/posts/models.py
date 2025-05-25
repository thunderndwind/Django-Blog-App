from django.db import models
from django.conf import settings
from apps.utils.fields import UploadcareImageField

class Post(models.Model):
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='posts',
        related_query_name='post'
    )
    title = models.CharField(max_length=200)
    content = models.TextField()
    image = UploadcareImageField(blank=True, null=True)  # Changed to our custom field
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    likes = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='liked_posts', blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.title} - {self.author.username}'

    def get_image_url(self):
        """Returns properly formatted CDN URL"""
        if self.image:
            if not str(self.image).startswith('http'):
                return f"https://ucarecdn.com/{str(self.image).strip('/')}/"
            return str(self.image)
        return None
