from django import forms
from .models import Post, Media, Comment

class PostCreateForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['caption', 'location']
        widgets = {
            'caption': forms.Textarea(attrs={
                'rows': 3,
                'placeholder': 'Write a caption...',
                'class': 'w-full border rounded-lg p-3'
            }),
            'location': forms.TextInput(attrs={
                'placeholder': 'Add location',
                'class': 'w-full border rounded-lg p-2'
            })
        }

class MediaForm(forms.ModelForm):
    class Meta:
        model = Media
        fields = ['file', 'media_type']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Hide media_type field - we'll determine it from file extension
        self.fields['media_type'].widget = forms.HiddenInput()

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['text']
        widgets = {
            'text': forms.Textarea(attrs={
                'rows': 2,
                'placeholder': 'Add a comment...',
                'class': 'w-full border rounded-lg p-2 resize-none'
            })
        }