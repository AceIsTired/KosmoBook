from django.db import models
from apps.users.models import BaseUser
from apps.notifications.models import NotificationManager

# Create your models here.
class MediaPost(models.Model):
    description = models.TextField(blank = True)
    uploader = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='%(class)s_uploads')
    creation_date = models.DateTimeField(auto_now_add = True)
    views = models.PositiveIntegerField(default = 0)
    likes = models.PositiveIntegerField(default = 0)

    class Meta:
        abstract = True


class Video(MediaPost):
    video_url = models.URLField()
    thumbnail_url = models.URLField(blank=True)
    duration_seconds = models.PositiveIntegerField(null=True, blank=True)

    def __str__(self):
        return f"Video: {self.title}"
    
    def test(self):
        NotificationManager.update('video_uploaded', video = self)

class Photo(MediaPost):
    image_url = models.URLField()
    width = models.PositiveIntegerField(null=True, blank=True)
    height = models.PositiveIntegerField(null=True, blank=True)

    def __str__(self):
        return f"Photo: {self.title}"

    def NotificationTest(self):
        NotificationManager.update('photo_uploaded', photo = self)


class Comment(models.Model):
    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='comments')
    text = models.TextField()
    creation_date = models.DateTimeField(auto_now_add=True)

    # A comment can be on either a video OR a photo (but not both)
    video = models.ForeignKey(Video, on_delete=models.CASCADE, null=True, blank=True, related_name='comments')
    photo = models.ForeignKey(Photo, on_delete=models.CASCADE, null=True, blank=True, related_name='comments')

    class Meta:
        ordering = ['-creation_date']

    def __str__(self):
        return f"Comment by {self.user.username}: {self.text[:50]}..."
