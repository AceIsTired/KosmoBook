from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseBadRequest
from django.db.models import Count, Q
from .models import Post, Media, Like, Comment, Bookmark
from .forms import PostCreateForm, CommentForm
from users.models import CustomUser

@login_required
def create_post(request):
    if request.method == 'POST':
        post_form = PostCreateForm(request.POST)
        
        # Manually check if files were uploaded
        files = request.FILES.getlist('media_files')
        if not files:
            # Add error if no files uploaded
            messages.error(request, 'Please upload at least one media file.')
            return render(request, 'media/createPost.html', {
                'form': post_form
            })
        
        if post_form.is_valid():
            post = post_form.save(commit=False)
            post.user = request.user
            post.save()
            
            # Handle multiple files
            for i, file in enumerate(files):
                # Determine media type from file extension
                file_name = file.name.lower()
                if any(file_name.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']):
                    media_type = 'image'
                elif any(file_name.endswith(ext) for ext in ['.mp4', '.mov', '.avi', '.mkv', '.webm']):
                    media_type = 'video'
                else:
                    media_type = 'image'  # default
                
                Media.objects.create(
                    post=post,
                    file=file,
                    media_type=media_type,
                    order=i
                )
            
            messages.success(request, 'Post created successfully!')
            return redirect('media:post_detail', pk=post.pk)
    else:
        post_form = PostCreateForm()
    
    return render(request, 'media/createPost.html', {
        'form': post_form
    })

def post_detail(request, pk):
    post = get_object_or_404(Post, pk=pk)
    comments = post.comments.filter(parent__isnull=True)  # Only top-level comments
    
    # Check if current user liked this post
    is_liked = False
    is_bookmarked = False
    if request.user.is_authenticated:
        is_liked = Like.objects.filter(user=request.user, post=post).exists()
        is_bookmarked = post.is_bookmarked_by(request.user)
    
    comment_form = CommentForm()
    
    return render(request, 'media/postDetail.html', {
        'post': post,
        'comments': comments,
        'comment_form': comment_form,
        'is_liked': is_liked,
        'is_bookmarked': is_bookmarked
    })

@login_required
def edit_post(request, pk):
    post = get_object_or_404(Post, pk=pk, user=request.user)
    
    if request.method == 'POST':
        form = PostCreateForm(request.POST, instance=post)
        if form.is_valid():
            form.save()
            messages.success(request, 'Post updated successfully!')
            return redirect('media:post_detail', pk=post.pk)
    else:
        form = PostCreateForm(instance=post)
    
    return render(request, 'media/editPost.html', {
        'form': form,
        'post': post
    })

@login_required
@require_POST
def delete_post(request, pk):
    post = get_object_or_404(Post, pk=pk, user=request.user)
    post.delete()
    messages.success(request, 'Post deleted successfully!')
    return redirect('users:profile', username=request.user.username)

@login_required
@require_POST
def like_post(request, pk):
    post = get_object_or_404(Post, pk=pk)
    
    # Check if already liked
    if Like.objects.filter(user=request.user, post=post).exists():
        return HttpResponseBadRequest("You already liked this post")
    
    Like.objects.create(user=request.user, post=post)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'liked': True,
            'like_count': post.like_count
        })
    
    return redirect('media:post_detail', pk=pk)

@login_required
@require_POST
def unlike_post(request, pk):
    post = get_object_or_404(Post, pk=pk)
    
    like = get_object_or_404(Like, user=request.user, post=post)
    like.delete()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'liked': False,
            'like_count': post.like_count
        })
    
    return redirect('media:post_detail', pk=pk)

@login_required
@require_POST
def add_comment(request, pk):
    post = get_object_or_404(Post, pk=pk)
    
    form = CommentForm(request.POST)
    if form.is_valid():
        comment = form.save(commit=False)
        comment.user = request.user
        comment.post = post
        comment.save()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'comment_id': comment.id,
                'username': comment.user.username,
                'text': comment.text,
                'created_at': comment.created_at.strftime('%b %d, %Y')
            })
    
    return redirect('media:post_detail', pk=pk)

@login_required
@require_POST
def delete_comment(request, pk):
    comment = get_object_or_404(Comment, pk=pk, user=request.user)
    post_pk = comment.post.pk
    comment.delete()
    
    messages.success(request, 'Comment deleted successfully!')
    return redirect('media:post_detail', pk=post_pk)

@login_required
@require_POST
def bookmark_post(request, post_id):
    """Bookmark OR unbookmark a post (toggle)"""
    post = get_object_or_404(Post, pk=post_id)
    
    # Check if already bookmarked
    bookmark_exists = Bookmark.objects.filter(user=request.user, post=post).exists()
    
    if bookmark_exists:
        # Remove bookmark (unbookmark)
        Bookmark.objects.filter(user=request.user, post=post).delete()
        messages.success(request, 'Post removed from your KosmoBoard')
    else:
        # Create bookmark
        Bookmark.objects.create(user=request.user, post=post)
        messages.success(request, 'Post saved to your KosmoBoard!')
    
    # Check where the request came from and redirect appropriately
    referer = request.META.get('HTTP_REFERER')
    if referer:
        return redirect(referer)
    
    # Default redirect to post detail
    return redirect('media:post_detail', pk=post_id)

@login_required
@require_POST
def remove_bookmark(request, bookmark_id):
    """Remove a bookmark"""
    bookmark = get_object_or_404(Bookmark, pk=bookmark_id, user=request.user)
    bookmark.delete()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'success': True,
            'message': 'Post removed from KosmoBoard'
        })
    
    return redirect('users:profile', username=request.user.username)


@login_required
def feed(request):
    # Get posts from users that the current user follows
    following_users = request.user.get_followed_users()
    posts = Post.objects.filter(
        Q(user__in=following_users) | Q(user=request.user)
    ).order_by('-created_at')

    for post in posts:
        post.is_bookmarked = post.is_bookmarked_by(request.user)
    
    return render(request, 'media/feed.html', {
        'posts': posts
    })

def explore(request):
    # Show popular posts (most liked)
    posts = Post.objects.annotate(
        like_count_val=Count('like')
    ).order_by('-like_count_val', '-created_at')[:50]
    
    if request.user.is_authenticated:
        # Use the is_bookmarked_by method for each post
        for post in posts:
            post.is_bookmarked = post.is_bookmarked_by(request.user)
    else:
        for post in posts:
            post.is_bookmarked = False

    return render(request, 'media/explore.html', {
        'posts': posts
    })