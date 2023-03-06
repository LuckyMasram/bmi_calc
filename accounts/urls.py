from django.urls import path
from .views import *

urlpatterns = [
    path('', index, name='index'),
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('verify-email/', verify_email, name='verify-email'),
    path('confirm-email/<uidb64>/<token>/', confirm_email, name='confirm-email'),
    path('forgot-password/', forgot_password, name='forgot-password'),
    path('reset-password/<uidb64>/<token>/', reset_password, name='reset-password'),
    path('profile/', profile, name='profile'),
    path('profile/edit/', edit_profile, name='edit-profile'),
    path('test/', test, name='test'),
    path('test-email/', test_email, name='test-email'),
    path('test-coverage/', test_coverage, name='test-coverage'),
]