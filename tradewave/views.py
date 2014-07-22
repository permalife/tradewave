from django.shortcuts import get_object_or_404, render
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
#from zaplings.models import FeaturedIdea, Love, Offer, Need, UserLove, NewUserEmail
from django.template import RequestContext, loader
from django.views import generic
import time
import logging

logging.basicConfig(level=logging.DEBUG, filename="/tmp/views.log")

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class IndexView(generic.ListView):
    model = User
    template_name = 'tradewave/index.html'

class LoginView(generic.ListView):
    model = User
    template_name = 'tradewave/login.html'

class HomeUserView(generic.ListView):
    model = User
    template_name = 'tradewave/home-user.html'

class SendView(generic.ListView):
    model = User
    template_name = 'tradewave/send.html'

class ConfirmSendView(generic.ListView):
    model = User
    template_name = 'tradewave/confirm-send.html'

class ConfirmReceiveView(generic.ListView):
    model = User
    template_name = 'tradewave/confirm-receive.html'

class TransactionConfirmedView(generic.ListView):
    model = User
    template_name = 'tradewave/transaction-confirmed.html'

# Create your views here.
