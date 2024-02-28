from django.urls import path
from . import views

urlpatterns = [
    path('mobileOTP',views.mobile_otp),
    path('emailOTP', views.email_otp),
    path('verifyOTP', views.verifyOTP)
]