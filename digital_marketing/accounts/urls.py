from django.urls import path
from .views import (
    UserRegistrationView,
    UserLoginView,
    PasswordResetRequestView,
    PasswordResetConfirmView
)

urlpatterns = [
    path('register', UserRegistrationView.as_view(), name='register'),
    path('login', UserLoginView.as_view(), name='login'),
    path('password-reset', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
]