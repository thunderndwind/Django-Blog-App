from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2', 
                 'first_name', 'last_name', 'bio', 'birth_date', 'profile_picture')
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'username': {'required': True},
            'bio': {'required': False, 'allow_blank': True},
            'birth_date': {'required': False},
            'profile_picture': {'required': False, 'allow_blank': True, 'allow_null': True},
        }

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords don't match"})
        return data

    def create(self, validated_data):
        validated_data.pop('password2', None)
        user = User.objects.create_user(**validated_data)
        return user

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Ensure profile picture is always a full URL
        data['profile_picture'] = instance.profile_picture_url
        return {
            'id': instance.id,
            'username': instance.username,
            'email': instance.email,
            'first_name': instance.first_name,
            'last_name': instance.last_name,
            'bio': instance.bio or '',
            'birth_date': instance.birth_date,
            'profile_picture': instance.profile_picture_url
        }

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
