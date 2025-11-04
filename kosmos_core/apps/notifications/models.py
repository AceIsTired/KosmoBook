from django.db import models
from django.conf import settings  # ← use this instead of importing BaseUser directly

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('video_upload', 'Video Uploaded'),
        ('photo_upload', 'Photo Uploaded'),
        ('video_liked', 'Video Liked'),
        ('photo_liked', 'Photo Liked'),
        ('comment_added', 'Comment Added'),
        ('appointment_booked', 'Appointment Booked'),
        ('appointment_reminder', 'Appointment Reminder'),
        ('follow', 'New Follower'),
        ('test', 'Test Notification'),
    ]

    # Use AUTH_USER_MODEL instead of importing BaseUser
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    description = models.CharField(max_length=200)
    message = models.TextField()
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPES)
    creation_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}: {self.description}"


# ----- Observer pattern helpers -----

class NotificationSubject:
    def __init__(self):
        self._observers = []

    def attach(self, observer):
        if observer not in self._observers:
            self._observers.append(observer)

    def detach(self, observer):
        if observer in self._observers:
            self._observers.remove(observer)

    def notify(self, event_type, **kwargs):
        for observer in self._observers:
            observer.update(event_type, **kwargs)


class NotificationObserver:
    def update(self, event_type, **kwargs):
        raise NotImplementedError("Subclasses must implement update()")


class NotificationManager(NotificationObserver):
    def update(self, event_type, **kwargs):
        # Align event names with NOTIFICATION_TYPES above
        if event_type == 'video_upload':
            self._create_video_upload_notification(**kwargs)
        elif event_type == 'photo_upload':
            self._create_photo_upload_notification(**kwargs)
        elif event_type == 'appointment_booked':
            self._create_appointment_notification(**kwargs)
        elif event_type == 'video_liked':
            self._create_video_like_notification(**kwargs)
        elif event_type == 'photo_liked':
            self._create_photo_like_notification(**kwargs)
        elif event_type == 'comment_added':
            self._create_comment_notification(**kwargs)

    # Minimal creators that only use the fields that exist on Notification

    def _create_photo_upload_notification(self, photo=None, user=None, **kwargs):
        # If a photo object is passed and has an uploader, use it; else fall back to user kwarg
        target_user = getattr(photo, "uploader", None) or user
        if target_user:
            Notification.objects.create(
                user=target_user,
                description="Photo Uploaded",
                message="Your photo has been uploaded.",
                notification_type='photo_upload',
            )

    def _create_video_upload_notification(self, video=None, user=None, **kwargs):
        target_user = getattr(video, "uploader", None) or user
        if target_user:
            Notification.objects.create(
                user=target_user,
                description="Video Uploaded",
                message="Your video has been uploaded.",
                notification_type='video_upload',
            )

    def _create_video_like_notification(self, video=None, liker=None, **kwargs):
        owner = getattr(video, "uploader", None)
        if owner and liker and owner != liker:
            Notification.objects.create(
                user=owner,
                description="New Like",
                message=f"{liker.username} liked your video.",
                notification_type='video_liked',
            )

    def _create_photo_like_notification(self, photo=None, liker=None, **kwargs):
        owner = getattr(photo, "uploader", None)
        if owner and liker and owner != liker:
            Notification.objects.create(
                user=owner,
                description="New Like",
                message=f"{liker.username} liked your photo.",
                notification_type='photo_liked',
            )

    def _create_comment_notification(self, comment=None, **kwargs):
        # Works for either photo or video comments if your comment object exposes .photo / .video and .user
        media_owner = None
        if comment is not None:
            if getattr(comment, "video", None):
                media_owner = getattr(comment.video, "uploader", None)
            elif getattr(comment, "photo", None):
                media_owner = getattr(comment.photo, "uploader", None)

        if media_owner and comment and media_owner != comment.user:
            Notification.objects.create(
                user=media_owner,
                description="New Comment",
                message=f"{comment.user.username} commented on your post.",
                notification_type='comment_added',
            )

    def _create_appointment_notification(self, appointment=None, **kwargs):
        # Notify the professional about a new booking
        if appointment and getattr(appointment, "professional", None):
            Notification.objects.create(
                user=appointment.professional,
                description="New Appointment",
                message=f"{appointment.client.username} booked {appointment.scheduled_time:%Y-%m-%d %H:%M}.",
                notification_type='appointment_booked',
            )
