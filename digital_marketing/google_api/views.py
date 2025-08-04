import os
import sys
import hashlib
import base64
import json
import logging
import traceback
from datetime import datetime
from urllib.parse import urlparse
from django.http import JsonResponse
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

logger = logging.getLogger(__name__)

# Google OAuth Configuration
GOOGLE_CONFIG = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
        "scopes": [
            'https://www.googleapis.com/auth/adwords',
            'https://www.googleapis.com/auth/youtube.readonly',
            'https://www.googleapis.com/auth/yt-analytics.readonly',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
            'openid'
        ]
    }
}

def google_login_url(request):
    """Generate Google OAuth URL with comprehensive error handling"""
    response_data = {
        'status': 'error',
        'message': 'Initialization failed',
        'debug': {
            'session_exists': bool(request.session.session_key),
            'client_id_configured': bool(os.getenv("GOOGLE_CLIENT_ID")),
            'redirect_uri': os.getenv("GOOGLE_REDIRECT_URI")
        }
    }

    try:
        # Verify critical configuration
        if not os.getenv("GOOGLE_CLIENT_ID"):
            raise ValueError("GOOGLE_CLIENT_ID not configured")
        if not os.getenv("GOOGLE_REDIRECT_URI"):
            raise ValueError("GOOGLE_REDIRECT_URI not configured")

        # Ensure session exists
        if not request.session.session_key:
            request.session.create()
            logger.info(f"Created new session: {request.session.session_key}")

        # Generate state with metadata
        state_data = {
            'token': hashlib.sha256(os.urandom(1024)).hexdigest(),
            'session_key': request.session.session_key,
            'timestamp': datetime.now().isoformat(),
            'ip': request.META.get('REMOTE_ADDR')
        }
        state = base64.urlsafe_b64encode(
            json.dumps(state_data).encode()
        ).decode().rstrip('=')

        # Configure flow
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
                }
            },
            scopes=GOOGLE_CONFIG['web']['scopes'],
            redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
            state=state
        )

        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )

        # Store state in session for validation
        request.session['oauth_state'] = state_data
        request.session.save()

        response = JsonResponse({
            'status': 'success',
            'auth_url': auth_url,
            'session_key': request.session.session_key
        })

        # Set tracking cookie
        response.set_cookie(
            'oauth_flow',
            f'google:{request.session.session_key}',
            max_age=300,
            httponly=True,
            samesite='Lax'
        )

        return response

    except Exception as e:
        logger.error(f"Login URL generation failed: {str(e)}\n{traceback.format_exc()}")
        response_data.update({
            'message': str(e),
            'error_type': type(e).__name__,
            'traceback': traceback.format_exc().splitlines()[-1]
        })
        return JsonResponse(response_data, status=500)

def google_callback(request):
    """Handle OAuth callback with multiple fallback mechanisms"""
    response_data = {
        'status': 'error',
        'debug': {
            'params': dict(request.GET),
            'headers': {k: v for k, v in request.headers.items() if k.lower() not in ['authorization', 'cookie']},
            'session_keys': list(request.session.keys()) if request.session.session_key else None
        }
    }

    try:
        # Essential parameter checks
        if 'code' not in request.GET:
            raise ValueError("Missing authorization code")
        
        state = request.GET.get('state')
        if not state:
            raise ValueError("Missing state parameter")

        # Attempt to load state from multiple sources
        state_data = None
        sources_tried = []
        
        # 1. Try from session first
        if 'oauth_state' in request.session:
            state_data = request.session['oauth_state']
            sources_tried.append('session')
        
        # 2. Try decoding from state parameter if session fails
        if not state_data:
            try:
                padding = len(state) % 4
                decoded = base64.urlsafe_b64decode(state + ('=' * padding)).decode()
                state_data = json.loads(decoded)
                sources_tried.append('url_encoded')
            except (ValueError, json.JSONDecodeError):
                pass
        
        # 3. Try cookie-based session recovery
        if not state_data and 'oauth_flow' in request.COOKIES:
            try:
                _, session_key = request.COOKIES['oauth_flow'].split(':')
                temp_session = SessionStore(session_key=session_key)
                if 'oauth_state' in temp_session:
                    state_data = temp_session['oauth_state']
                    sources_tried.append('cookie_recovery')
            except Exception as e:
                logger.warning(f"Cookie recovery failed: {str(e)}")

        if not state_data:
            raise ValueError(
                f"Could not recover state from any source. Tried: {sources_tried or 'none'}"
            )

        # Validate state contents
        required_fields = {'token', 'session_key', 'timestamp'}
        if not all(field in state_data for field in required_fields):
            raise ValueError(f"Invalid state format. Missing fields: {required_fields - set(state_data.keys())}")

        # Initialize flow
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
                }
            },
            scopes=GOOGLE_CONFIG['web']['scopes'],
            redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
            state=state
        )
        
        # Exchange code for tokens
        flow.fetch_token(authorization_response=request.build_absolute_uri())

        # Store credentials
        request.session['google_credentials'] = {
            'token': flow.credentials.token,
            'refresh_token': flow.credentials.refresh_token,
            'token_uri': flow.credentials.token_uri,
            'client_id': flow.credentials.client_id,
            'client_secret': os.getenv("GOOGLE_CLIENT_SECRET"),
            'scopes': flow.credentials.scopes,
            'expiry': flow.credentials.expiry.isoformat() if flow.credentials.expiry else None 
        }
        request.session.modified = True

        return JsonResponse({
            'status': 'success',
            'message': 'Authentication successful',
            'session_key': request.session.session_key,
            'state_source': sources_tried[0] if sources_tried else 'unknown'
        })

    except Exception as e:
        logger.error(f"Callback failed: {str(e)}\n{traceback.format_exc()}")
        response_data.update({
            'message': str(e),
            'error_type': type(e).__name__,
            'state_sources_tried': sources_tried,
            'state_data_received': state_data
        })
        return JsonResponse(response_data, status=400)
    
def get_google_credentials(request):
    """Helper function to get credentials from session"""
    creds_data = request.session.get('google_credentials')
    if not creds_data:
        return None
    
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data['refresh_token'],
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=creds_data['scopes']
    )
    
    if creds.expired:
        creds.refresh(Request())
        request.session['google_credentials']['token'] = creds.token
        request.session.modified = True
    
    return creds

def get_google_accounts(request):
    """Get list of Google Ads accounts accessible to the user"""
    credentials = get_google_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated with Google'}, status=401)
    
    try:
        # Use Google Ads API
        from google.ads.googleads.client import GoogleAdsClient
        from google.ads.googleads.errors import GoogleAdsException
        
        # Initialize the GoogleAdsClient
        googleads_client = GoogleAdsClient.load_from_dict({
            "developer_token": os.getenv("GOOGLE_DEVELOPER_TOKEN"),
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": credentials.refresh_token,
            "use_proto_plus": True
        })
        
        customer_service = googleads_client.get_service("CustomerService")
        
        accessible_customers = customer_service.list_accessible_customers()
        
        accounts = []
        for customer_id in accessible_customers.resource_names:
            customer = customer_service.get_customer(resource_name=customer_id)
            accounts.append({
                'id': customer.id,
                'resource_name': customer.resource_name,
                'descriptive_name': customer.descriptive_name,
                'currency_code': customer.currency_code,
                'time_zone': customer.time_zone,
                'manager': customer.manager
            })
        
        return JsonResponse({'accounts': accounts})
    
    except GoogleAdsException as ex:
        return JsonResponse({'error': str(ex)}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def get_google_campaigns(request):
    """Get campaigns for a specific Google Ads account"""
    credentials = get_google_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated with Google'}, status=401)
    
    customer_id = request.GET.get('customer_id')
    if not customer_id:
        return JsonResponse({'error': 'customer_id is required'}, status=400)
    
    try:
        from google.ads.googleads.client import GoogleAdsClient
        from google.ads.googleads.errors import GoogleAdsException
        
        googleads_client = GoogleAdsClient.load_from_dict({
            "developer_token": os.getenv("GOOGLE_DEVELOPER_TOKEN"),
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": credentials.refresh_token,
            "use_proto_plus": True
        })
        
        ga_service = googleads_client.get_service("GoogleAdsService")
        
        query = """
            SELECT
                campaign.id,
                campaign.name,
                campaign.status,
                campaign.start_date,
                campaign.end_date,
                campaign.advertising_channel_type,
                metrics.impressions,
                metrics.clicks,
                metrics.ctr,
                metrics.average_cpc,
                metrics.cost_micros
            FROM campaign
            WHERE campaign.status != 'REMOVED'
            ORDER BY campaign.id
        """
        
        campaigns = []
        response = ga_service.search(customer_id=customer_id, query=query)
        
        for row in response:
            campaigns.append({
                'id': row.campaign.id,
                'name': row.campaign.name,
                'status': row.campaign.status.name,
                'start_date': row.campaign.start_date,
                'end_date': row.campaign.end_date,
                'channel_type': row.campaign.advertising_channel_type.name,
                'impressions': row.metrics.impressions,
                'clicks': row.metrics.clicks,
                'ctr': row.metrics.ctr,
                'average_cpc': row.metrics.average_cpc,
                'cost': row.metrics.cost_micros / 1000000  # Convert micros to standard currency
            })
        
        return JsonResponse({'campaigns': campaigns})
    
    except GoogleAdsException as ex:
        return JsonResponse({'error': str(ex)}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def get_google_ads(request):
    """Get ads for a specific Google Ads account"""
    credentials = get_google_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated with Google'}, status=401)
    
    customer_id = request.GET.get('customer_id')
    if not customer_id:
        return JsonResponse({'error': 'customer_id is required'}, status=400)
    
    try:
        from google.ads.googleads.client import GoogleAdsClient
        from google.ads.googleads.errors import GoogleAdsException
        
        googleads_client = GoogleAdsClient.load_from_dict({
            "developer_token": os.getenv("GOOGLE_DEVELOPER_TOKEN"),
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": credentials.refresh_token,
            "use_proto_plus": True
        })
        
        ga_service = googleads_client.get_service("GoogleAdsService")
        
        query = """
            SELECT
                ad_group_ad.ad.id,
                ad_group_ad.ad.name,
                ad_group_ad.ad.type,
                ad_group_ad.status,
                ad_group_ad.ad.responsive_search_ad.headlines,
                ad_group_ad.ad.responsive_search_ad.descriptions,
                metrics.impressions,
                metrics.clicks,
                metrics.ctr,
                metrics.average_cpc,
                metrics.cost_micros
            FROM ad_group_ad
            WHERE ad_group_ad.status != 'REMOVED'
            ORDER BY metrics.impressions DESC
            LIMIT 100
        """
        
        ads = []
        response = ga_service.search(customer_id=customer_id, query=query)
        
        for row in response:
            ad_data = {
                'id': row.ad_group_ad.ad.id,
                'name': row.ad_group_ad.ad.name,
                'type': row.ad_group_ad.ad.type_.name,
                'status': row.ad_group_ad.status.name,
                'impressions': row.metrics.impressions,
                'clicks': row.metrics.clicks,
                'ctr': row.metrics.ctr,
                'average_cpc': row.metrics.average_cpc,
                'cost': row.metrics.cost_micros / 1000000
            }
            
            # Handle different ad types
            if row.ad_group_ad.ad.type_ == row.ad_group_ad.ad.type_.RESPONSIVE_SEARCH_AD:
                headlines = [h.text for h in row.ad_group_ad.ad.responsive_search_ad.headlines]
                descriptions = [d.text for d in row.ad_group_ad.ad.responsive_search_ad.descriptions]
                ad_data['headlines'] = headlines
                ad_data['descriptions'] = descriptions
            
            ads.append(ad_data)
        
        return JsonResponse({'ads': ads})
    
    except GoogleAdsException as ex:
        return JsonResponse({'error': str(ex)}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def get_google_insights(request):
    """Get insights for a specific Google Ads account"""
    credentials = get_google_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated with Google'}, status=401)
    
    customer_id = request.GET.get('customer_id')
    days = int(request.GET.get('days', 30))  # Default: 30 days
    
    if not customer_id:
        return JsonResponse({'error': 'customer_id is required'}, status=400)
    
    try:
        from google.ads.googleads.client import GoogleAdsClient
        from google.ads.googleads.errors import GoogleAdsException
        
        googleads_client = GoogleAdsClient.load_from_dict({
            "developer_token": os.getenv("GOOGLE_DEVELOPER_TOKEN"),
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": credentials.refresh_token,
            "use_proto_plus": True
        })
        
        ga_service = googleads_client.get_service("GoogleAdsService")
        
        # Calculate date range
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        
        query = f"""
            SELECT
                segments.date,
                campaign.id,
                campaign.name,
                metrics.impressions,
                metrics.clicks,
                metrics.ctr,
                metrics.average_cpc,
                metrics.cost_micros,
                metrics.conversions,
                metrics.conversions_value
            FROM campaign
            WHERE segments.date BETWEEN '{start_date}' AND '{end_date}'
            ORDER BY segments.date
        """
        
        insights = []
        response = ga_service.search(customer_id=customer_id, query=query)
        
        for row in response:
            insights.append({
                'date': row.segments.date,
                'campaign_id': row.campaign.id,
                'campaign_name': row.campaign.name,
                'impressions': row.metrics.impressions,
                'clicks': row.metrics.clicks,
                'ctr': row.metrics.ctr,
                'average_cpc': row.metrics.average_cpc,
                'cost': row.metrics.cost_micros / 1000000,
                'conversions': row.metrics.conversions,
                'conversions_value': row.metrics.conversions_value
            })
        
        return JsonResponse({'insights': insights})
    
    except GoogleAdsException as ex:
        return JsonResponse({'error': str(ex)}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def get_youtube_channels(request):
    """Get YouTube channels associated with the authenticated user"""
    credentials = get_google_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated with Google'}, status=401)
    
    try:
        youtube = build('youtube', 'v3', credentials=credentials)
        
        request = youtube.channels().list(
            part="snippet,contentDetails,statistics",
            mine=True,
            maxResults=50
        )
        response = request.execute()
        
        channels = []
        for item in response.get('items', []):
            channels.append({
                'id': item['id'],
                'title': item['snippet']['title'],
                'description': item['snippet']['description'],
                'thumbnail': item['snippet']['thumbnails']['default']['url'],
                'subscribers': item['statistics']['subscriberCount'],
                'views': item['statistics']['viewCount'],
                'video_count': item['statistics']['videoCount']
            })
        
        return JsonResponse({'channels': channels})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def get_youtube_insights(request):
    """Get YouTube analytics for a specific channel"""
    credentials = get_google_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Not authenticated with Google'}, status=401)
    
    channel_id = request.GET.get('channel_id')
    days = int(request.GET.get('days', 30))  # Default: 30 days
    
    if not channel_id:
        return JsonResponse({'error': 'channel_id is required'}, status=400)
    
    try:
        # Calculate date range
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # YouTube Analytics API
        youtube_analytics = build('youtubeAnalytics', 'v2', credentials=credentials)
        
        response = youtube_analytics.reports().query(
            ids=f"channel=={channel_id}",
            startDate=start_date,
            endDate=end_date,
            metrics="views,estimatedMinutesWatched,likes,dislikes,shares,comments,subscribersGained",
            dimensions="day",
            sort="day"
        ).execute()
        
        # YouTube Data API for video-level insights
        youtube = build('youtube', 'v3', credentials=credentials)
        
        videos_request = youtube.search().list(
            part="id",
            channelId=channel_id,
            maxResults=50,
            order="date",
            type="video"
        )
        videos_response = videos_request.execute()
        
        video_insights = []
        for item in videos_response.get('items', []):
            video_id = item['id']['videoId']
            
            stats_request = youtube.videos().list(
                part="statistics",
                id=video_id
            )
            stats_response = stats_request.execute()
            
            if stats_response.get('items'):
                stats = stats_response['items'][0]['statistics']
                video_insights.append({
                    'video_id': video_id,
                    'views': stats.get('viewCount'),
                    'likes': stats.get('likeCount'),
                    'dislikes': stats.get('dislikeCount'),
                    'comments': stats.get('commentCount')
                })
        
        return JsonResponse({
            'daily_metrics': response.get('rows', []),
            'video_insights': video_insights
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)