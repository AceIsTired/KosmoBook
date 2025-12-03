from django.db import models
from django.urls import reverse
from users.models import CustomUser

class Post(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='posts')
    caption = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    location = models.CharField(max_length=255, blank=True)

    # Stats (will be calculated, not stored)
    @property
    def like_count(self):
        return self.like_set.count()

    @property
    def comment_count(self):
        return self.comments.count()

    def __str__(self):
        return f"Post by {self.user.username} - {self.created_at.strftime('%Y-%m-%d')}"

    def get_absolute_url(self):
        return reverse('media:post_detail', kwargs={'pk': self.pk})

    class Meta:
        ordering = ['-created_at']

class Media(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='media_files')
    MEDIA_TYPES = [
        ('image', 'Image'),
        ('video', 'Video'),
    ]
    file = models.FileField(upload_to='posts/%Y/%m/%d/')
    media_type = models.CharField(max_length=10, choices=MEDIA_TYPES)
    order = models.IntegerField(default=0)  # For multiple media ordering
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True)  # For videos

    class Meta:
        ordering = ['order']

    def __str__(self):
        return f"{self.media_type} for post {self.post.id}"

class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True)
    posts = models.ManyToManyField(Post, related_name='tags')

    def __str__(self):
        return f"#{self.name}"

    class Meta:
        ordering = ['name']

class Like(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user', 'post']

    def __str__(self):
        return f"{self.user.username} likes post {self.post.id}"

class Comment(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')  # For replies

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Comment by {self.user.username} on post {self.post.id}"