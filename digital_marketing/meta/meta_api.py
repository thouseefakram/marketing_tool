from django.conf import settings
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adsinsights import AdsInsights
from facebook_business.adobjects.user import User
from datetime import date, timedelta
import requests


def get_user_access_token(request):
    """Helper function to get user access token from session"""
    return request.session.get('fb_user_access_token')

def get_user_ad_accounts(user_access_token):
    """Get all ad accounts for the authenticated user"""
    FacebookAdsApi.init(access_token=user_access_token)
    user = User(fbid='me')
    return user.get_ad_accounts()

def get_ad_insights(request, days=30):
    """Get ad insights for the authenticated user"""
    user_access_token = get_user_access_token(request)
    if not user_access_token:
        raise Exception("User not authenticated with Facebook")
    
    FacebookAdsApi.init(access_token=user_access_token)
    
    # Get first ad account (you might want to let user choose)
    ad_accounts = get_user_ad_accounts(user_access_token)
    if not ad_accounts:
        raise Exception("No ad accounts found for this user")
    
    ad_account_id = ad_accounts[0].get_id()

    fields = [
        AdsInsights.Field.campaign_id,
        AdsInsights.Field.campaign_name,
        AdsInsights.Field.impressions,
        AdsInsights.Field.clicks,
        AdsInsights.Field.ctr,
        AdsInsights.Field.spend,
        AdsInsights.Field.date_start,
        AdsInsights.Field.date_stop,
    ]

    since_date = (date.today() - timedelta(days=days)).isoformat()
    until_date = date.today().isoformat()

    params = {
        'time_range': {
            'since': since_date,
            'until': until_date
        },
        'level': 'campaign',
    }

    insights = AdAccount(ad_account_id).get_insights(fields=fields, params=params)

    all_insights = []
    while insights:
        all_insights.extend(insights)
        insights = insights.next() if insights.has_next() else None

    return [dict(insight) for insight in all_insights]

def get_combined_ad_insights(request, days=30):
    """Get combined ad insights for the authenticated user"""
    user_access_token = get_user_access_token(request)
    if not user_access_token:
        raise Exception("User not authenticated with Facebook")
    
    FacebookAdsApi.init(access_token=user_access_token)
    
    # Get first ad account
    ad_accounts = get_user_ad_accounts(user_access_token)
    if not ad_accounts:
        raise Exception("No ad accounts found for this user")
    
    ad_account_id = ad_accounts[0].get_id()

    fields = [
        AdsInsights.Field.ad_id,
        AdsInsights.Field.ad_name,
        AdsInsights.Field.impressions,
        AdsInsights.Field.clicks,
        AdsInsights.Field.ctr,
        AdsInsights.Field.spend,
        AdsInsights.Field.date_start,
        AdsInsights.Field.date_stop,
    ]

    since_date = (date.today() - timedelta(days=days)).isoformat()
    until_date = date.today().isoformat()

    params = {
        'time_range': {
            'since': since_date,
            'until': until_date
        },
        'level': 'ad',
        'breakdowns': ['publisher_platform'],
    }

    insights = AdAccount(ad_account_id).get_insights(fields=fields, params=params)

    all_insights = []
    while insights:
        all_insights.extend(insights)
        insights = insights.next() if insights.has_next() else None

    return [dict(insight) for insight in all_insights]


# meta_api.py
def get_instagram_insights_data(request, instagram_account_id, days=30):
    """Get Instagram insights for a specific account"""
    user_access_token = get_user_access_token(request)
    if not user_access_token:
        raise Exception("User not authenticated with Facebook")
    
    FacebookAdsApi.init(access_token=user_access_token)
    
    metrics = [
        'impressions', 'reach', 'profile_views', 'website_clicks',
        'follower_count', 'email_contacts', 'phone_call_clicks',
        'text_message_clicks', 'get_directions_clicks'
    ]
    
    since_date = (date.today() - timedelta(days=days)).strftime('%Y-%m-%d')
    until_date = date.today().strftime('%Y-%m-%d')
    
    params = {
        'metric': ','.join(metrics),
        'period': 'day',
        'since': since_date,
        'until': until_date
    }
    
    insights = InstagramAccount(instagram_account_id).get_insights(params=params)
    
    all_insights = []
    while insights:
        all_insights.extend(insights)
        insights = insights.next() if insights.has_next() else None
    
    return [dict(insight) for insight in all_insights] 