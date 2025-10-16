from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import login as auth_login, logout as auth_logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authlib.integrations.django_client import OAuth
from django.conf import settings

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='auth0',
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    server_metadata_url=f'https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email'
    }
)

def home(request):
    return render(request, 'auth/home.html')

def login(request):
    redirect_uri = request.build_absolute_uri(reverse('callback'))
    print(redirect_uri)
    return oauth.auth0.authorize_redirect(request, redirect_uri)

def callback(request):
    token = oauth.auth0.authorize_access_token(request)
    user_info = token.get('userinfo')
    if user_info:
        # Create or update user (simplified, use your user model logic)
        user, _ = User.objects.get_or_create(
            username=user_info['sub'],
            defaults={'first_name': user_info.get('name', '')}
        )
        auth_login(request, user)
        request.session['user_info'] = user_info
    return redirect('home')

def logout(request):
    request.session.clear()
    auth_logout(request)
    logout_url = f'https://{settings.AUTH0_DOMAIN}/v2/logout?client_id={settings.AUTH0_CLIENT_ID}&returnTo={request.build_absolute_uri(reverse("home"))}'
    return redirect(logout_url)

class UserView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        user_info = request.session.get('user_info', {})
        return Response({
            'name': user_info.get('name', ''),
            'email': user_info.get('email', '')
        })