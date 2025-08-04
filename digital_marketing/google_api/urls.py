# google_ads/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('google_login', views.google_login_url),
    path('google_callback', views.google_callback),
    path('google_accounts', views.get_google_accounts),
    path('google_campaigns', views.get_google_campaigns),
    path('google_ads', views.get_google_ads),
    path('google_insights', views.get_google_insights),
    path('youtube_channels', views.get_youtube_channels),
    path('youtube_insights', views.get_youtube_insights),
]


