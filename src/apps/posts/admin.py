from django.contrib import admin
from .models import Post

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'content_preview', 'created_at', 'like_count')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('content', 'author__username')
    date_hierarchy = 'created_at'
    ordering = ('-created_at',)

    def content_preview(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    content_preview.short_description = 'Content'

    def like_count(self, obj):
        return obj.likes.count()
    like_count.short_description = 'Likes'
