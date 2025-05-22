from django.db import models

class UploadcareImageField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 255  # UUID length plus some extra
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        """Convert value before saving to database"""
        if value:
            # Remove any URL parts, keep only UUID
            if 'ucarecdn.com' in str(value):
                value = str(value).split('ucarecdn.com/')[-1].strip('/')
            return value.strip('/')
        return value

    def from_db_value(self, value, expression, connection):
        """Convert value when reading from database"""
        if value:
            return f"https://ucarecdn.com/{value.strip('/')}/"
        return value

    def to_python(self, value):
        """Convert the value when accessed in Python"""
        if value:
            # If it's already a full URL, return it
            if 'ucarecdn.com' in str(value):
                return value
            # Otherwise, construct the URL
            return f"https://ucarecdn.com/{value.strip('/')}/"
        return value
