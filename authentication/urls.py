from django.urls import path 
from . import views 

urlpatterns = [
    path('', views.home, name = 'home'),
    path('register/', views.register, name='register'),
    path('verify/<str:token>/', views.email_verification, name='verify_email'),
    path('login/', views.login, name = 'login'),
    path('mfa_Verification/<int:user_id>/', views.mfa_verification, name='mfa_verification'),
    path('logout/', views.logoutuser, name='logout'),
    path('verification/', views.verify, name='verification'),
    path('forgotPassword/', views.ForgotPassword, name='forgot_password'),
    path('passwordresetsent/<str:reset_id>/', views.PasswordResetSent, name='password_reset_sent'),
    path('resetpassword/<str:reset_id>/', views.ResetPassword, name='reset_password'),
]
