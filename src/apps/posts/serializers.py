from rest_framework import serializers
from .models import Post
import re

class PostAuthorSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    profile_picture = serializers.SerializerMethodField()

    def get_profile_picture(self, obj):
        return obj.get_profile_picture()

class PostSerializer(serializers.ModelSerializer):
    author = PostAuthorSerializer(read_only=True)
    likes_count = serializers.IntegerField(source='likes.count', read_only=True)
    image = serializers.CharField(required=False, allow_blank=True)  # Changed from URLField to CharField

    class Meta:
        model = Post
        fields = ('id', 'title', 'author', 'content', 'image', 
                 'created_at', 'updated_at', 'likes_count', 'likes')
        read_only_fields = ('author', 'created_at', 'updated_at', 'likes')

    def validate_image(self, value):
        if value:
            # Clean the value
            value = value.strip('/')
            
            # UUID pattern (8-4-4-4-12 format)
            uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            
            # If it's a valid UUID, return it directly
            if re.match(uuid_pattern, value):
                return value
            
            # If it's a URL, extract and validate the UUID
            if 'ucarecdn.com' in value:
                uuid = value.split('ucarecdn.com/')[-1].strip('/')
                if re.match(uuid_pattern, uuid):
                    return uuid
                    
            raise serializers.ValidationError('Invalid Uploadcare image identifier')
        return value

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Ensure proper URL format for image
        if data.get('image'):
            data['image'] = instance.get_image_url()
        return data
