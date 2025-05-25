from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.core.exceptions import ValidationError
from apps.utils.fields import UploadcareImageField

class User(AbstractUser):
    DEFAULT_PROFILE_UUID = "41bf360b-e5d0-410e-aa84-31f5183dfbd1"
    
    # Add related_name to avoid clashes
    groups = models.ManyToManyField(
        Group,
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name='custom_user_set'  # Changed from user_set
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set'  # Changed from user_set
    )
    
    email = models.EmailField(unique=True, blank=False, null=False)
    username = models.CharField(max_length=150, unique=True, blank=False, null=False)
    bio = models.TextField(max_length=500, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    profile_picture = UploadcareImageField(blank=True, null=True, default=DEFAULT_PROFILE_UUID)
    following = models.ManyToManyField('self', symmetrical=False, related_name='followers', blank=True)
    
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']
    
    def clean(self):
        super().clean()
        if not self.email:
            raise ValidationError('Email is required')

    def save(self, *args, **kwargs):
        if not self.profile_picture:
            self.profile_picture = self.DEFAULT_PROFILE_UUID
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

    @property
    def profile_picture_url(self):
        """Returns properly formatted CDN URL"""
        if self.profile_picture:
            if not str(self.profile_picture).startswith('http'):
                return f"https://ucarecdn.com/{str(self.profile_picture).strip('/')}/"
            return str(self.profile_picture)
        return f"https://ucarecdn.com/{self.DEFAULT_PROFILE_UUID}/"

    def get_profile_picture(self):
        return self.profile_picture_url
