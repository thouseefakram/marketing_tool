# ads/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('facebook_login', views.facebook_login_url),
    path('callback', views.facebook_callback),
    path('facebook_accounts', views.get_ad_accounts),
    path('facebook_campaigns', views.get_campaigns),
    path('facebook_insights', views.get_ad_insights_api),
    # Instagram Endpoints
    path('instagram_pages', views.get_facebook_pages),
    path('instagram_accounts', views.get_instagram_accounts),
    path('instagram_insights', views.get_instagram_insights),
]



