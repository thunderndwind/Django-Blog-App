from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import User

class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].required = True
        self.fields['first_name'].required = True
        self.fields['last_name'].required = True

class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_active', 'groups')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('username',)
    
    def get_fieldsets(self, request, obj=None):
        if not obj:
            # Adding a new user
            return (
                (None, {
                    'fields': ('username', 'email', 'password1', 'password2'),
                }),
                ('Personal info', {
                    'fields': ('first_name', 'last_name', 'bio', 'birth_date', 'profile_picture'),
                }),
            )
        
        if request.user.is_superuser:
            # Superuser editing any user
            return (
                (None, {
                    'fields': ('username', 'email', 'password'),
                }),
                ('Personal info', {
                    'fields': ('first_name', 'last_name', 'bio', 'birth_date', 'profile_picture'),
                }),
                ('Following', {
                    'fields': ('following',),
                }),
                ('Permissions', {
                    'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
                }),
                ('Important dates', {
                    'fields': ('last_login', 'date_joined'),
                }),
            )
        else:
            # Staff user editing
            return (
                (None, {
                    'fields': ('username', 'email'),
                }),
                ('Personal info', {
                    'fields': ('first_name', 'last_name', 'bio', 'birth_date', 'profile_picture'),
                }),
                ('Following', {
                    'fields': ('following',),
                }),
            )

    def get_readonly_fields(self, request, obj=None):
        if not request.user.is_superuser:
            # Staff users can't change these fields
            return ('is_staff', 'is_superuser', 'groups', 'user_permissions', 'last_login', 'date_joined')
        return super().get_readonly_fields(request, obj)

admin.site.register(User, CustomUserAdmin)
