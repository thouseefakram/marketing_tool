import requests
from django.conf import settings
from django.http import JsonResponse
from urllib.parse import urlencode
from datetime import date, timedelta
import os
from dotenv import load_dotenv
from .meta_api import get_ad_insights

load_dotenv()

class FacebookAPI:
    BASE_URL = 'https://graph.facebook.com/v18.0'
    
    @staticmethod
    def get_oauth_url():
        return "https://www.facebook.com/v18.0/dialog/oauth"
    
    @staticmethod
    def make_request(url, params, method='GET'):
        try:
            if method == 'GET':
                response = requests.get(url, params=params)
            else:
                response = requests.post(url, data=params)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

class MetaViews:
    @staticmethod
    def facebook_login_url(request):
        params = {
            'client_id': os.getenv("FACEBOOK_APP_ID"),
            'redirect_uri': os.getenv("FACEBOOK_REDIRECT_URI"),
            'scope': os.getenv("FACEBOOK_SCOPE", 'ads_management,ads_read,pages_show_list,instagram_basic,instagram_manage_insights'),
            'response_type': 'code',
        }
        login_url = f"{FacebookAPI.get_oauth_url()}?{urlencode(params)}"
        return JsonResponse({'login_url': login_url})

    @staticmethod
    def facebook_callback(request):
        code = request.GET.get('code')
        if not code:
            return JsonResponse({'error': 'Authorization code is required'}, status=400)

        # Exchange code for short-lived token
        token_params = {
            'client_id': os.getenv("FACEBOOK_APP_ID"),
            'client_secret': os.getenv("FACEBOOK_APP_SECRET"),
            'redirect_uri': os.getenv("FACEBOOK_REDIRECT_URI"),
            'code': code,
        }
        
        token_data = FacebookAPI.make_request(
            f'{FacebookAPI.BASE_URL}/oauth/access_token',
            token_params
        )
        
        if 'error' in token_data:
            return JsonResponse(token_data, status=400)
        
        # Exchange for long-lived token
        long_token_params = {
            'grant_type': 'fb_exchange_token',
            'client_id': os.getenv("FACEBOOK_APP_ID"),
            'client_secret': os.getenv("FACEBOOK_APP_SECRET"),
            'fb_exchange_token': token_data.get('access_token')
        }
        
        long_token_data = FacebookAPI.make_request(
            f'{FacebookAPI.BASE_URL}/oauth/access_token',
            long_token_params
        )
        
        return JsonResponse(long_token_data)

    @staticmethod
    def get_ad_accounts(request):
        access_token = request.GET.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'access_token is required'}, status=400)

        params = {
            'access_token': access_token,
            'fields': 'id,name,account_status,timezone_name'
        }
        
        data = FacebookAPI.make_request(
            f'{FacebookAPI.BASE_URL}/me/adaccounts',
            params
        )
        
        return JsonResponse(data)

    @staticmethod
    def get_campaigns(request):
        access_token = request.GET.get('access_token')
        ad_account_id = request.GET.get('ad_account_id')
        
        if not access_token or not ad_account_id:
            return JsonResponse(
                {'error': 'access_token and ad_account_id are required'},
                status=400
            )

        params = {
            'access_token': access_token,
            'fields': 'id,name,status,objective,effective_status'
        }
        
        data = FacebookAPI.make_request(
            f'{FacebookAPI.BASE_URL}/{ad_account_id}/campaigns',
            params
        )
        
        return JsonResponse(data)

    @staticmethod
    def get_ad_insights_api(request):
        access_token = request.GET.get('access_token')
        days = int(request.GET.get('days', 30))
        
        if not access_token:
            return JsonResponse({'error': 'access_token is required'}, status=400)
        
        try:
            request.session['fb_user_access_token'] = access_token
            insights = get_ad_insights(request, days=days)
            return JsonResponse({'data': insights})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    @staticmethod
    def get_facebook_pages(request):
        access_token = request.GET.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'access_token is required'}, status=400)

        params = {
            'access_token': access_token,
            'fields': 'id,name,instagram_business_account'
        }
        
        data = FacebookAPI.make_request(
            f'{FacebookAPI.BASE_URL}/me/accounts',
            params
        )
        
        return JsonResponse(data)

    @staticmethod
    def get_instagram_accounts(request):
        access_token = request.GET.get('access_token')
        if not access_token:
            return JsonResponse({'error': 'access_token is required'}, status=400)

        try:
            # Step 1: Get Facebook Pages
            pages_url = 'https://graph.facebook.com/v18.0/me/accounts'
            pages_params = {
                'access_token': access_token,
                'fields': 'id,name,instagram_business_account'
            }
            pages_response = requests.get(pages_url, params=pages_params)
            pages_data = pages_response.json()

            if 'error' in pages_data:
                return JsonResponse({'error': 'Failed to fetch Facebook Pages', 'details': pages_data}, status=400)

            # Step 2: Extract Instagram Accounts
            instagram_accounts = []
            for page in pages_data.get('data', []):
                if not page.get('instagram_business_account'):
                    continue  # Skip pages without Instagram

                ig_account_id = page['instagram_business_account']['id']
                
                # Step 3: Get Instagram Details
                ig_url = f'https://graph.facebook.com/v18.0/{ig_account_id}'
                ig_params = {
                    'access_token': access_token,
                    'fields': 'id,username,profile_picture_url,name,biography,followers_count,media_count'
                }
                ig_response = requests.get(ig_url, params=ig_params)
                ig_data = ig_response.json()

                if 'error' in ig_data:
                    return JsonResponse({'error': 'Failed to fetch Instagram account', 'details': ig_data}, status=400)
                
                instagram_accounts.append(ig_data)

            if not instagram_accounts:
                return JsonResponse({'error': 'No Instagram Business Accounts found'}, status=404)

            return JsonResponse({'instagram_accounts': instagram_accounts})

        except Exception as e:
            return JsonResponse({'error': 'Server error', 'details': str(e)}, status=500)

    @staticmethod
    def get_instagram_insights(request):
        access_token = request.GET.get('access_token')
        instagram_account_id = request.GET.get('instagram_account_id')
        days = int(request.GET.get('days', 30))
        
        if not access_token or not instagram_account_id:
            return JsonResponse(
                {'error': 'access_token and instagram_account_id are required'},
                status=400
            )
        
        metrics = [
            'impressions', 'reach', 'profile_views', 'website_clicks',
            'follower_count', 'email_contacts', 'phone_call_clicks',
            'text_message_clicks', 'get_directions_clicks'
        ]
        
        since_date = (date.today() - timedelta(days=days)).strftime('%Y-%m-%d')
        until_date = date.today().strftime('%Y-%m-%d')
        
        params = {
            'access_token': access_token,
            'metric': ','.join(metrics),
            'period': 'day',
            'since': since_date,
            'until': until_date
        }
        
        data = FacebookAPI.make_request(
            f'{FacebookAPI.BASE_URL}/{instagram_account_id}/insights',
            params
        )
        
        return JsonResponse(data)

# URL routing functions (to be used in urls.py)
def facebook_login_url(request):
    return MetaViews.facebook_login_url(request)

def facebook_callback(request):
    return MetaViews.facebook_callback(request)

def get_ad_accounts(request):
    return MetaViews.get_ad_accounts(request)

def get_campaigns(request):
    return MetaViews.get_campaigns(request)

def get_ad_insights_api(request):
    return MetaViews.get_ad_insights_api(request)

def get_facebook_pages(request):
    return MetaViews.get_facebook_pages(request)

def get_instagram_accounts(request):
    return MetaViews.get_instagram_accounts(request)

def get_instagram_insights(request):
    return MetaViews.get_instagram_insights(request)