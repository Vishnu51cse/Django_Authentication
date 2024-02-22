from django.urls import path
from django.shortcuts import redirect 
from . import views


urlpatterns = [
    path('home/', views.home, name="home"),
    path('login/', views.login, name="login"),
    path('signup/', views.signup, name="signup"),
    path('', views.home, name='home')

]

   
