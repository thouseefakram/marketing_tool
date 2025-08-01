from django.contrib import admin
from django.urls import path
from accounts.views import (
    UserRegistrationView,
    UserLoginView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    ProtectedTestView
)

urlpatterns = [
    path('register', UserRegistrationView.as_view(), name='register'),
    path('login', UserLoginView.as_view(), name='login'),
    path('password-reset', PasswordResetRequestView.as_view(), name='password_reset'),
    path('password-confirm', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('protected', ProtectedTestView.as_view(), name='protected'),
]