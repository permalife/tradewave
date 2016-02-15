from django.shortcuts import get_object_or_404, render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
#from zaplings.models import FeaturedIdea, Love, Offer, Need, UserLove, NewUserEmail
from django.template import RequestContext, loader
from django.views import generic
from tradewave.models import City, Venue, Entity, VenueMap, Credit, \
    Account, CreditMap, TradewaveUser, Relationship, Industry, Vendor, \
    Marketplace, Affiliation, TransactionLog
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

class UserHomeView(generic.ListView):
    model = User
    template_name = 'tradewave/user-home.html'

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
    template_name = 'tradewave/vendor-initial.html'
    context_object_name = 'featured_venues'

    def get_queryset(self):
        """Return the featured venues."""
        return Venue.objects.all()[:3]

class VendorTransaction(generic.ListView):
    model = User
    template_name = 'tradewave/vendor-transaction.html'

class SettingsUser(generic.ListView):
    model = User
    template_name = 'tradewave/settings-user.html'

class SettingsVendor(generic.ListView):
    model = User
    template_name = 'tradewave/settings-vendor.html'

class SettingsMarketplace(generic.ListView):
    model = User
    template_name = 'tradewave/settings-marketplace.html'

# *** handlers [process] ***
def process_login(request):
    try:
        # TO-DO: use django forms
        user_name = request.POST.get('user_name')
        user_password = request.POST.get('user_password')
        user = authenticate(
            username=user_name,
            password=user_password
        )

        # is existing user?
        if user is not None and user.is_active:
            login(request, user)
            logger.info('Logged in as user [%s]', user.username)
            user_tradewave = TradewaveUser.objects.get(user=user.pk)

            # sesssion-wide variable user role (default to personal):
            request.session['user_role'] = 'personal'

            user_name = user.username

            # user's personal entity
            user_entity = user.tradewaveuser.user_entity

            # generate the list of credits
            # we limit to a single account for simplicity for now
            user_account = user_entity.account_set.first()
            user_amount_total = user_account.amount_total
            user_wallet = CreditMap.objects.filter(account=user_account)
            user_credits = dict([
                (entry.credit.name, entry.amount) for entry in user_wallet
            ])

            # generate the render link
            template_prefix = 'user'
            template_handle = 'tradewave/%s-home.html' % template_prefix
            logger.info('redirecting to %s', template_handle)
            request_obj = {
                'featured_venues': Venue.objects.all()[:3],
                'username': user_name,
                'amount': user_amount_total,
                'credits': user_credits,
            }

            return render(request, template_handle, request_obj)
        else:
            request_obj = { 'status_msg': 'Invalid credentials'}
            return render(request, 'tradewave/login.html', request_obj)
    except Exception as e:
        logger.error("Server error: %s", e)
        request_obj = { 'status_msg': 'Error logging in: %s' % e }
        return render(request, 'tradewave/login.html', request_obj)

# *** handlers [process] ***
def process_logout(request):
    try:
        logout(request)
    except Exception as e:
        logger.error("Server error: %s", e)
    finally:
        request_obj = { 'status_msg': 'Please login to your account'}
        return render(request, 'tradewave/login.html', request_obj)

# *** handlers [record] ***
def record_venue(request, venue_id):
    logger.info("venue is [%s]", venue_id)
    request.session['venue'] = venue_id
    venue = Venue.objects.get(id=venue_id)
    #logger.info("request.session: %s", str(request.session.items()))
    request_obj = { 'selected_venue':  venue,
                    'name': request.session['name'],
                    'amount': request.session['amount'],
                    'credits': request.session['credits'] }
    return render(request,
                  'tradewave/%s-home.html' % request.session['user_type'],
                  request_obj)
