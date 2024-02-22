from django.conf import Settings
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from .models import User
from .forms import UserForm  # Import the UserForm
from django.db.utils import IntegrityError  
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.contrib.auth.models import User
# Rename this view to avoid conflicts with the `login` function
import logging
def home(request):
    return render(request, "home.html")

# Rename this view to avoid conflicts with the `login` function
def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        # Check if the user exists
        if User.objects.filter(email=email).exists():
            user = authenticate(request, username=email, password=password)

            if user is not None:
                login(request, user)
                return HttpResponseRedirect(reverse(Settings.LOGIN_REDIRECT_URL))
            else:
                return render(request, 'login.html', {'error': 'Incorrect password.'})
        else:
            return render(request, 'login.html', {'error': 'This email is not registered.'})

    return render(request, 'login.html')

# Update the signup view

def signup(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)  # Create a User instance but don't save it yet
            # You can set the password using make_password here
            user.password = make_password(request.POST['password'])
            user.save()  # Save the User instance with the hashed password
            return redirect('home', {'success': 'Sign up successful!'})

    else:
        form = UserForm()

    return render(request, 'signup.html', {'form': form})
