

#in tokens.py

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six
class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) +
            six.text_type(user.is_active)
        )
account_activation_token = TokenGenerator()



#in urls.py

urlpatterns = [
    
    path('activate/<str:uid>/<str:token>',views.activate, name='activate'),        

]






# in forms.py

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class SignupForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')




#in models.py

from django.db import models
from django.contrib import auth

# Create your models here.

class Yourmodel(models.Model):
    first_name = models.CharField(max_length=200)
    second_name = models.CharField(max_length=200)
    email = models.EmailField(max_length=100)
        


#in views.py

from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from .forms import SignupForm
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import send_mail
from .models import Yourmodel
from django.contrib.auth import get_user_model
from django.conf import settings


def signup(request):
    User = get_user_model()
    form = SignupForm()
    if request.method =='POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            username = request.POST.get('username')
            email = request.POST.get('email')
            domain_name = get_current_site(request).domain
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            token = account_activation_token.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            link = f'http://{domain_name}/accounts/activate/{uid}/{token}'
            send_mail(
                'Email Verification',
                f'Please click {link} to activate your account',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            return HttpResponse('Verification email has been sent!')
        else:
            return HttpResponse('You have already registered!')
    else:
        return render(request, 'accounts/signup.html', {'form': form})
    






def activate(request, uid, token):
    User = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')










#in settings.py

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp-mail.outlook.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'your_email'
EMAIL_HOST_PASSWORD = 'your_password'  # os.environ['password_key'] suggested
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = 'noreply@vaulkann.com'












