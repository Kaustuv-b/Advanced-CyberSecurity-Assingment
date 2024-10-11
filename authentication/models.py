from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid 
from django.contrib.auth.hashers import check_password
from django.conf import settings


# A profile model to for email verification 
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    verification_token = models.CharField(max_length=32, blank=True)
    
    def __str__(self):
        return self.user.username
     
#OTP model to generate a OTP for multifactor authentication 
class Otp(models.Model): 
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return (timezone.now() - self.created_at).seconds < 300
    

#Password Reset model to reset the user passwords 
class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"


#For repetition of password
class PasswordHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    password = models.CharField(max_length=128)
    date = models.DateTimeField(auto_now_add=True)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)