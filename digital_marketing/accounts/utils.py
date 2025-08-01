import jwt
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from datetime import datetime, timedelta
from django.utils import timezone
from .models import PasswordResetToken
from dotenv import load_dotenv
import os

# Load the .env file
load_dotenv() 

def generate_jwt_token(user):
    payload = {
        'user_id': str(user.id),
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm='HS256')

def generate_password_reset_token(user):
    # This now just returns the token instead of sending email
    from .models import PasswordResetToken
    reset_token = PasswordResetToken.objects.create(
        user=user,
        expires_at=timezone.now() + timedelta(seconds=settings.PASSWORD_RESET_TIMEOUT)
    )
    return str(reset_token.token)

def send_password_reset_email(user, request):
    # Create or get existing token
    reset_token, created = PasswordResetToken.objects.get_or_create(
        user=user,
        defaults={
            'expires_at': timezone.now() + timedelta(seconds=settings.PASSWORD_RESET_TIMEOUT)
        }
    )
    
    if not created:
        reset_token.expires_at = timezone.now() + timedelta(seconds=settings.PASSWORD_RESET_TIMEOUT)
        reset_token.save()
    
    reset_url = request.build_absolute_uri(
        reverse('password_reset_confirm') + f'?token={reset_token.token}'
    )
    
    subject = 'Password Reset Request'
    message = f"""
    Hello,
    
    You're receiving this email because you requested a password reset for your account.
    
    Please click the link below to reset your password:
    {reset_url}
    
    If you didn't request this, please ignore this email.
    
    Thanks,
    The Auth Team
    """
    
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )