from django.db import models
from apps.users.models import BaseUser


'''This is created/called to create a notification type object when a
media/comment creation function is called such as _create_photo_upload_notification()'''
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
        ('test', 'Test Notification')
    ]

    user = models.ForeignKey(BaseUser, on_delete=models.CASCADE, related_name='notifications')
    description = models.CharField(max_length=200)
    message = models.TextField()
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPES)
    creation_date = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.user.username}: {self.description}"


'''Responsible for notifying observers on its state data. When update(notify) is called,
 sends the relevant info to NotificationManager'''
class NotificationSubject:
    def __init__(self):
        self._observers = []
    # adds observers/subscribers (users) to the notification system. For example, manager = NotificationManager()
    # subject.attach(manager)
    def attach(self, observer):
        if observer not in self._observers:
            self._observers.append(observer)
    # removes observers/subscribers (users) to the notification system
    def detach(self, observer):
        self._observers.remove(observer)

    # Notify calls on each observers update function and passes through the required parameters.
    # subject.notify('photo_uploaded', etc...)
    # **kwargs is flexible and helps pass more data that may be needed to create the notification
    def notify(self, event_type, **kwargs):
        for observer in self._observers:
            observer.update(event_type, **kwargs)



'''The interface for the observer/subscriber, ensures everything passed has an update function'''
class NotificationObserver:
    def update(self, event_type, **kwargs):
        raise NotImplementedError("Subclasses must implement update()")

'''The NotificationManager is what actually creates and sends out the notification to the user'''
class NotificationManager(NotificationObserver):
    def update(self, event_type, **kwargs):
        # This method is called when observed subjects change and
        # checks for what type of notification it should send out
        if event_type == 'video_uploaded':
            self._create_video_upload_notification(**kwargs)
        elif event_type == 'photo_uploaded':
            self._create_photo_upload_notification(**kwargs)
        elif event_type == 'appointment_booked':
            self._create_appointment_notification(**kwargs)
        elif event_type == 'video_liked':
            self._create_like_notification(**kwargs)
        elif event_type == 'photo_liked':
            self._create_photo_like_notification(**kwargs)
        elif event_type == 'comment_added':
            self._create_comment_notification(**kwargs)

    #ADD FUTURE EXISTING EVENTS LIKE: APPOINTMENT UPDATED

    # Creates the actual notification (object) that is sent out to a user
    def _create_photo_upload_notification(self, photo, **kwargs):
        # Notify followers when a user uploads a photo
        Notification.objects.create(
            user=photo.uploader,
            title="Photo Uploaded",
            message=f"Your post has been uploaded",
            notification_type='photo_upload',
        )

    def _create_photo_like_notification(self, photo, liker, **kwargs):
        # Notify user when someone likes their post
        if photo.uploader != liker:
            Notification.objects.create(
                user=photo.uploader,
                title="New Like",
                message=f"{liker.username} liked your photo '{photo.title}'",
                notification_type='photo_liked',
                related_photo=photo
            )

    def _create_comment_notification(self, comment, **kwargs):
        # Notify user when someone comments on their post
        if comment.video:
            media_owner = comment.video.uploader
            media_type = "video"
            media_title = comment.video.title
            related_video = comment.video
            related_photo = None
        else:
            media_owner = comment.photo.uploader
            media_type = "photo"
            media_title = comment.photo.title
            related_video = None
            related_photo = comment.photo

        if media_owner != comment.user:
            Notification.objects.create(
                user=media_owner,
                title="New Comment",
                message=f"{comment.user.username} commented on your {media_type} '{media_title}'",
                notification_type='comment_added',
                related_video=related_video,
                related_photo=related_photo
            )