from django.shortcuts import get_object_or_404, render
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
#from zaplings.models import FeaturedIdea, Love, Offer, Need, UserLove, NewUserEmail
from django.template import RequestContext, loader
from django.views import generic
from tradewave.models import Venue 
import time
import logging

logging.basicConfig(level=logging.DEBUG, filename="log/views.log")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# *** classes ***
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

class CreateUserView(generic.ListView):
    model = User
    template_name = 'tradewave/create-user.html'
	
class CreateVendorView(generic.ListView):
    model = User
    template_name = 'tradewave/create-vendor.html'
	
class LoadDdipView(generic.ListView):
    model = User
    template_name = 'tradewave/load-ddip.html'
	
class MarketplaceInitial(generic.ListView):
    template_name = 'tradewave/marketplace-initial.html'
    context_object_name = 'featured_venues'

    def get_queryset(self):
        """Return the featured venues."""
        return Venue.objects.all()[:3]

class MarketplaceHome(generic.ListView):
    model = User
    template_name = 'tradewave/marketplace-home.html'

class MarketplaceIssue(generic.ListView):
    model = User
    template_name = 'tradewave/marketplace-issue.html'

class MarketplaceSend(generic.ListView):
    model = User
    template_name = 'tradewave/marketplace-send.html'	

class VendorChoosePayment(generic.ListView):
    model = User
    template_name = 'tradewave/vendor-choose-payment.html'	

class VendorCustLogin(generic.ListView):
    model = User
    template_name = 'tradewave/vendor-cust-login.html'	
	
class VendorHome(generic.ListView):
    model = User
    template_name = 'tradewave/vendor-home.html'	

class VendorInitial(generic.ListView):
    model = User
    template_name = 'tradewave/vendor-initial.html'
	
class VendorTransaction(generic.ListView):
    model = User
    template_name = 'tradewave/vendor-transaction.html'

# *** handlers ***
def record_venue(request, venue_id): 
    logger.info("venue is [%s]", venue_id) 
    request.session['venue'] = venue_id
    venue = Venue.objects.get(id=venue_id) 
    #logger.info("request.session: %s", str(request.session.items())) 
    request_obj = { 'selected_venue':  venue} 
    # return back to index for the time-being 
    return render(request, 'tradewave/marketplace-home.html', request_obj)  

