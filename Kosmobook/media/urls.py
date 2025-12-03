from django.urls import path
from . import views

app_name = 'media'

urlpatterns = [
    # Post URLs
    path('create/', views.create_post, name='create_post'),
    path('post/<int:pk>/', views.post_detail, name='post_detail'),
    path('post/<int:pk>/edit/', views.edit_post, name='edit_post'),
    path('post/<int:pk>/delete/', views.delete_post, name='delete_post'),

    # Like URLs
    path('post/<int:pk>/like/', views.like_post, name='like_post'),
    path('post/<int:pk>/unlike/', views.unlike_post, name='unlike_post'),

    # Comment URLs
    path('post/<int:pk>/comment/', views.add_comment, name='add_comment'),
    path('comment/<int:pk>/delete/', views.delete_comment, name='delete_comment'),

    path('bookmark/<int:post_id>/', views.bookmark_post, name='bookmark_post'),
    path('bookmark/<int:bookmark_id>/remove/', views.remove_bookmark, name='remove_bookmark'),

    # Feed URLs
    path('feed/', views.feed, name='feed'),
    path('explore/', views.explore, name='explore'),
]