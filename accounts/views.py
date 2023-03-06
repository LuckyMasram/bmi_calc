from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
from django.core.mail import send_mail
from .forms import ProfileForm
from django.conf import settings
from django.utils.crypto import get_random_string
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from .models import User

def index(request):
    if request.user.is_authenticated:
        try:
            profile = User.objects.get(email=request.user)
            return render(request, 'bmi/profile.html', {'profile': profile})
        except User.DoesNotExist:
            return redirect('profile')
    else:
        return redirect('login')

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}!')
            return redirect('login')
        else:
            form = UserCreationForm()
    return render(request, 'registration/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            messages.error(request, 'Invalid email or password')
    else:
        form = AuthenticationForm()
    return render(request, 'registration/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

def profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        if form.is_valid():
            profile = form.save(commit=False)
            profile.user = request.user
            profile.bmi = (profile.weight / (profile.height ** 2))
            profile.save()
            messages.success(request, 'Data saved successfully!')
            subject = 'BMI analysis'
            message = f'Hello {profile.full_name}, your BMI is {profile.bmi:.2f}.'
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [request.user.email, ]
            send_mail(subject, message, from_email, recipient_list)
            return redirect('index')
        else:
            form = ProfileForm()
    return render(request, 'bmi/profile.html')

def verify_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            subject = 'Verify your email'
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            verification_link = reverse('confirm-email', args=[uidb64, token])
            message = f'Hello {user.username}, please click on the link below to verify your email.\n{request.build_absolute_uri(verification_link)}'
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email, ]
            send_mail(subject, message, from_email, recipient_list)
            messages.success(request, 'Verification email sent successfully!')
        else:
            messages.error(request, 'Email not found!')
    return redirect('login')

def confirm_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and PasswordResetTokenGenerator().check_token(user, token):
        user.email_verified = True
        user.save()
        messages.success(request, 'Email verified successfully!')
        return redirect('login')
    else:
        messages.error(request, 'Invalid verification link!')
    return redirect('verify-email')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            subject = 'Reset your password'
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = reverse('reset-password', args=[uidb64, token])
            message = f'Hello {user.username}, please click on the link below to reset your password.\n{request.build_absolute_uri(reset_link)}'
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email, ]
            send_mail(subject, message, from_email, recipient_list)
            messages.success(request, 'Password reset link sent successfully!')
        else:
            messages.error(request, 'Email not found!')
    return render(request, 'bmi/forgot_password.html')

def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and PasswordResetTokenGenerator().check_token(user, token):
        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
        if password == confirm_password:
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successfully!')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match!')
            return render(request, 'registration/reset_password.html')
    else:
        messages.error(request, 'Invalid reset link!')
    return redirect('forgot-password')

def edit_profile(request):
    try:
        profile = User.objects.get(email=request.email)
    except User.DoesNotExist:
        return redirect('profile')
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=profile)
        if form.is_valid():
            profile = form.save(commit=False)
            profile.bmi = (profile.weight / (profile.height ** 2))
            profile.save()
            messages.success(request, 'Data saved successfully!')
            subject = 'BMI analysis'
            message = f'Hello {profile.full_name}, your BMI is {profile.bmi:.2f}.'
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [request.user.email, ]
            send_mail(subject, message, from_email, recipient_list)
            return redirect('index')
        else:
            form = ProfileForm(instance=profile)
    return render(request, 'bmi/edit_profile.html', {'form': form})

def test(request):
    return render(request, 'bmi/test.html')

def test_email(request):
    subject = 'Test email'
    message = f'This is a test email from BMI app. Random string: {get_random_string()}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [request.user.email, ]
    send_mail(subject, message, from_email, recipient_list)
    messages.success(request, 'Test email sent successfully!')
    return redirect('test')

def test_coverage(request):
    # run test coverage command
    cov = coverage.Coverage()
    cov.start()
    call_command('test')
    cov.stop()
    cov.save()


