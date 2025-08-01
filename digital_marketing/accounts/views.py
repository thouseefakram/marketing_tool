from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser, PasswordResetToken
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)
from django.core.mail import send_mail
from django.conf import settings
import uuid

class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            token, created = Token.objects.get_or_create(user=user)
            login(request, user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = CustomUser.objects.get(email=email)
                # Delete any existing tokens for this user
                PasswordResetToken.objects.filter(user=user).delete()
                # Create new token
                expires_at = timezone.now() + timedelta(hours=1)
                reset_token = PasswordResetToken.objects.create(
                    user=user,
                    expires_at=expires_at
                )
                # Send email with reset link
                reset_link = f"http://your-frontend.com/reset-password?token={reset_token.token}"
                send_mail(
                    'Password Reset Request',
                    f'Click the link to reset your password: {reset_link}',
                    settings.EMAIL_HOST_USER,
                    [user.email],
                    fail_silently=False,
                )
                return Response({'message': 'Password reset link sent to your email'}, 
                              status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'message': 'User with this email does not exist'}, 
                              status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            try:
                reset_token = PasswordResetToken.objects.get(token=token)
                if reset_token.is_valid():
                    user = reset_token.user
                    user.set_password(new_password)
                    user.save()
                    reset_token.delete()
                    return Response({'message': 'Password reset successfully'}, 
                                    status=status.HTTP_200_OK)
                else:
                    reset_token.delete()
                    return Response({'message': 'Token has expired'}, 
                                  status=status.HTTP_400_BAD_REQUEST)
            except PasswordResetToken.DoesNotExist:
                return Response({'message': 'Invalid token'}, 
                              status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)