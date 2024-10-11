from django.contrib import admin
from .models import * 

admin.site.register(Profile)
admin.site.register(Otp)
admin.site.register(PasswordReset)
admin.site.register(PasswordHistory)