from django.shortcuts import render, redirect, get_object_or_404
import requests 
import json 
from django.contrib import messages
from django.contrib.auth.models import User  
from django.utils.crypto import get_random_string
from .models import *
from django.core.mail import EmailMessage
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import authenticate, login as user_login, logout
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.contrib.auth.hashers import make_password


@login_required
def home(request):
    return render(request, 'home.html')

# registration
def register(request):

    if request.method == "POST":
        
        #captcha Validation 
        clientKey = request.POST.get('g-recaptcha-response')
        secretKey = '6LcacloqAAAAANeS4PIBStWcoQz7M_UKgpCPmThZ'
        captchaData = {
            'secret': secretKey,
            'response': clientKey,
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=captchaData)
        response = json.loads(r.text)
        verify = response.get('success')

        if not verify:
            messages.error(request, "Invalid reCAPTCHA. Please try again.")
            return redirect('register')
        
        #form data
        name = request.POST.get('name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')


        # Validate user data
        user_data_has_error = False

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, "Username already exists")

        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, "Email already exists")
        
        #To confirm that passwords match
        if password != confirm_password:
            user_data_has_error = True
            messages.error(request, "Passwords do not match")

        if user_data_has_error:
            return redirect('register')
        
        # Create user but set inactive for email verification
        new_user = User.objects.create_user(
            first_name=name,
            email=email,
            username=username,
            password=password,
        )
        new_user.is_active = False 
        new_user.save()

        #email verification

        # Generate a unique email verification token
        verification_token = get_random_string(length=32)

        profile = Profile(user=new_user, verification_token=verification_token)
        profile.save()

        # Send verification email
        verification_link = f'http://127.0.0.1:8000/verify/{verification_token}/'
        email_body = f'Click the following link to verify your account: {verification_link}'
        email_message = EmailMessage(
            'Verify your email address',
            email_body,
            settings.EMAIL_HOST_USER,
            [new_user.email]
        )
        try:
            email_message.send()
        except Exception as e:
            messages.error(request, f"Failed to send verification email: {str(e)}")
            return redirect('register')

        return redirect('verification')

    return render(request, 'register.html')

def verify(request):
    return render(request, 'verify.html')

def email_verification(request, token):

    try:
        profile = get_object_or_404(Profile, verification_token=token)
        user = profile.user
        user.is_active = True 
        user.save()
 
        profile.save()

        messages.success(request, "Email verified successfully! You can now log in.")
        return redirect('login')

    except Profile.DoesNotExist:
        return HttpResponse('Verification failed. Invalid token.')

# Login View
def login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:

            otp = get_random_string(length=6, allowed_chars='0123456789')
            Otp.objects.create(user=user, otp=otp)

            # Send OTP email
            email_body = f'Your OTP code is: {otp}'
            email_message = EmailMessage(
                'Your OTP Code',
                email_body,
                settings.EMAIL_HOST_USER,
                [user.email]
            )
            email_message.send()

            return redirect('mfa_verification', user.id)
        
        else:
            messages.error(request, "User doesn't exist")

    return render (request, 'login.html')

def mfa_verification(request, user_id):

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User does not exist.")
        return redirect('login')

    if request.method == "POST":
        otp_entered = request.POST.get("otp")
        try:
            otp_instance = Otp.objects.get(user=user, otp=otp_entered)
            if otp_instance.is_valid():
                user_login(request, user)
                return redirect('home')
            else:
                messages.error(request, "Invalid or expired OTP.")
        except Otp.DoesNotExist:
            messages.error(request, "Invalid OTP.")

    context = {'user': user}

    return render(request, 'otp.html', context)

def logoutuser(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')


def ForgotPassword(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            password_reset_url = reverse('reset_password', kwargs={'reset_id': new_password_reset.reset_id})
            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            email_body = f'Reset your password using the link below:\n\n{full_password_reset_url}'
            email_message = EmailMessage(
                'Reset your password',
                email_body,
                settings.EMAIL_HOST_USER,
                [email]
            )
            try:
                email_message.send()
            except Exception as e:
                messages.error(request, f"Failed to send password reset email: {str(e)}")
                return redirect('forgot_password')

            return redirect('password_reset_sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot_password')

    return render(request, 'forgot_password.html')


def PasswordResetSent(request, reset_id):
    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        messages.error(request, 'Invalid reset id')
        return redirect('forgot_password')


def ResetPassword(request, reset_id):
    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if password != confirm_password:
                messages.error(request, 'Passwords do not match')
                return redirect('reset_password', reset_id=reset_id)

            if len(password) < 8:
                messages.error(request, 'Password must be at least 8 characters long')
                return redirect('reset_password', reset_id=reset_id)

            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                messages.error(request, 'Reset link has expired')
                password_reset_id.delete()
                return redirect('forgot_password')

            
            user = password_reset_id.user
            password_history = PasswordHistory.objects.filter(user=user).order_by('-date')[:3]
            for old_password in password_history:
                if old_password.check_password(password):
                    messages.error(request, 'You cannot reuse one of your last 3 passwords')
                    return redirect('reset_password', reset_id=reset_id)

            # Reset user password
            user.set_password(password)
            user.save()

            
            PasswordHistory.objects.create(user=user, password=make_password(password))

          
            password_reset_id.delete()

            messages.success(request, 'Password reset. Proceed to login')
            return redirect('login')

    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid reset id')
        return redirect('forgot_password')

    return render(request, 'reset_password.html')
         