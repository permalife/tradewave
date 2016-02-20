from django.shortcuts import get_object_or_404, render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.template import RequestContext, loader
from django.views import generic
from tradewave.models import City, Venue, Entity, VenueMap, Credit, \
    Account, CreditMap, TradewaveUser, Relationship, Industry, Vendor, \
    Marketplace, Affiliation, TransactionLog
import time
import logging

from operator import attrgetter
from collections import OrderedDict

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

# *** handler to process user login ***
def process_login(request):
    try:
        # TODO: use django forms
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
            user_name = user.username
            request.session['name'] = user_name

            # user's personal entity
            user_personal_entity = user.tradewaveuser.user_entity

            # session-wide variable user personal entity
            # (save it user_name for now because we use it for page title)
            request.session['entity_personal'] = user_name
            logger.info('personal entity name: %s', user_personal_entity.name)

            # generate the list of user personal credits
            # we limit to a single account for simplicity for now
            user_account = user_personal_entity.account_set.first()
            user_amount_total = user_account.amount_total
            user_wallet = CreditMap.objects.filter(account=user_account)
            user_credits = OrderedDict([
                (entry.credit.name, float(entry.amount))
                for entry in sorted(user_wallet, key=attrgetter('amount'), reverse=True)
            ])
            logger.info(user_credits)
            request.session['user_total'] = float(user_amount_total)
            request.session['user_credits'] = user_credits

            # session-wide variable vendor entity
            # for simplicity only handle one-to-one user to vendor association
            if user_tradewave.vendors.exists():
                user_entity = user_tradewave.vendors.first()
                request.session['entity_vendor'] = user_entity.name
                logger.info('vendor entity name: %s', user_entity.name)

            # session-wide variable user marketplace entity
            # for simplicity only handle one-to-one user to marketplace association
            if user_tradewave.marketplaces.exists():
                user_entity = user_tradewave.marketplaces.first()
                request.session['entity_marketplace'] = user_entity.name
                logger.info('marketplace entity name: %s', user_entity.name)

            # generate the list of vendor / entity entity credits
            # we limit to a single account for simplicity for now
            if user_tradewave.vendors.exists() or user_tradewave.marketplaces.exists():
                entity_account = user_entity.account_set.first()
                entity_amount_total = entity_account.amount_total
                entity_wallet = CreditMap.objects.filter(account=entity_account)
                entity_credits = OrderedDict([
                    (entry.credit.name, float(entry.amount))
                    for entry in sorted(entity_wallet, key=attrgetter('amount'), reverse=True)
                ])
                request.session['entity_total'] = float(entity_amount_total)
                request.session['entity_credits'] = entity_credits

            # generate the render link
            template_handle = 'tradewave/user-home.html'
            logger.info('redirecting to %s', template_handle)

            # standard request object to the user page
            request_obj = {
                #'featured_venues': Venue.objects.all()[:3],
                'name': user_name,
                'user_total': user_amount_total,
                'user_credits': user_credits,
            }

            return render(request, template_handle, request_obj)
        else:
            request_obj = {'status_msg': 'Invalid login / password'}
            return render(request, 'tradewave/login.html', request_obj)

    except Exception as e:
        logger.error("Server error: %s", e)
        request_obj = {
            'status_msg': 'Server error occured, please contact the administrator'
        }
        return render(request, 'tradewave/login.html', request_obj)


# *** handler to process user logout ***
def process_logout(request):
    try:
        logout(request)
    except Exception as e:
        logger.error("Server error: %s", e)
    finally:
        request_obj = {'status_msg': 'Please login to your account'}
        return render(request, 'tradewave/login.html', request_obj)


# *** handler for vendor transaction screen ***
def process_vendor_transaction(request):
    try:
        # TODO'S:
        #   use django forms
        #   track product categories
        product_category = request.POST.get('product_category')
        product_amount = float(request.POST.get('product_amount'))
        request_obj = {
            'selected_venue': request.session['selected_venue'],
            'vendor_name': request.session['entity_vendor'],
            'user_name': request.session['entity_personal'],
            'user_total': request.session['user_total'],
            'user_credits': request.session['user_credits'],
            'product_amount': product_amount
        }
        return render(request, 'tradewave/vendor-choose-payment.html', request_obj)

    except Exception as e:
        logger.error("Server error: %s", e)
        request_obj = {'status_msg': e.message}
        return render(request, 'tradewave/login.html', request_obj)


# *** handler to redirect to the personal page ***
def redirect_to_personal(request):
    try:
        request_obj = {
            'name': request.session['entity_personal'],
            'user_total': request.session['user_total'],
            'user_credits': request.session['user_credits'],
        }
        return render(request, 'tradewave/user-home.html', request_obj)

    except Exception as e:
        logger.error("Server error: %s", e)
        request_obj = {
            'status_msg': 'Server error occurred: please contact the administrator'
        }
        return render(request, 'tradewave/login.html', request_obj)


# *** handler to redirect to the vendor page, if applicable ***
def redirect_to_vendor(request):
    try:
        if request.session.has_key('entity_vendor'):
            logger.info('user has a vendor association')
            if request.session.has_key('selected_venue'):
                logger.info(
                    'user has already chosen a venue: %s',
                    request.session['selected_venue']
                )
                template_name = 'tradewave/vendor-home.html'
                request_obj = {
                    'selected_venue': request.session['selected_venue'],
                    'name': request.session['entity_vendor'],
                    'total': request.session['entity_total'],
                    'credits': request.session['entity_credits']
                }
            else:
                logger.info('user has not chosen a venue')
                template_name = 'tradewave/vendor-initial.html'
                request_obj = {
                    'name': request.session['entity_vendor'],
                    'featured_venues': Venue.objects.all()[:3]
                }
        else:
            logger.info('user has no vendor associations')
            request_obj = {
                'name': request.session['name'],
                'total': request.session['total'],
                'credits': request.session['credits'],
                'status_msg': 'Your account is not associated with any vendor'
            }
            template_name = 'tradewave/user-home.html'

        return render(request, template_name, request_obj)

    except Exception as e:
        logger.error("Server error: %s", e)
        request_obj = {
            'status_msg': 'Server error occurred: please contact the administrator'
        }
        return render(request, 'tradewave/login.html', request_obj)


# *** handler to redirect to the marketplace page, if applicable ***
def redirect_to_marketplace(request):
    try:
        if request.session.has_key('entity_marketplace'):
            logger.info('user has a marketplace association')
            if request.session.has_key('selected_venue'):
                logger.info(
                    'user has already chosen a venue: %s',
                    request.session['selected_venue']
                )
                template_name = 'tradewave/marketplace-home.html'
                request_obj = {
                    'selected_venue': request.session['selected_venue'],
                    'name': request.session['entity_marketplace'],
                    'total': request.session['entity_total'],
                    'credits': request.session['entity_credits']
                }
            else:
                logger.info('user has not chosen a venue')
                template_name = 'tradewave/marketplace-initial.html'
                request_obj = {
                    'name': request.session['entity_marketplace'],
                    'featured_venues': Venue.objects.all()[:3]
                }
        else:
            logger.info('user has no marketplace associations')
            request_obj = {
                'name': request.session['name'],
                'total': request.session['total'],
                'credits': request.session['credits'],
                'status_msg': 'Your account is not associated with any marketplace'
            }
            template_name = 'tradewave/user-home.html'

        return render(request, template_name, request_obj)

    except Exception as e:
        logger.error("Server error: %s", e)
        request_obj = {
            'status_msg': 'Server error occurred: please contact the administrator'
        }
        return render(request, 'tradewave/login.html', request_obj)


# *** handlers [record] ***
def record_venue(request, venue_id):
    logger.info("Selected venue id is [%s]", venue_id)
    request.session['venue_id'] = venue_id
    venue = Venue.objects.get(id=venue_id)
    request.session['selected_venue'] = venue.name
    #logger.info("request.session: %s", str(request.session.items()))

    request_obj = {
        'selected_venue': request.session['selected_venue'],
        'total': request.session['entity_total'],
        'credits': request.session['entity_credits']
    }

    # determine the destination template
    if request.session.has_key('entity_vendor'):
        template_name = 'tradewave/vendor-home.html'
        request_obj['name'] = request.session['entity_vendor']
    elif request.session.has_key('entity_marketplace'):
        template_name = 'tradewave/marketplace-home.html'
        request_obj['name'] = request.session['entity_marketplace']
    else:
        # possibly the session has expired, have the user re-login
        template_name = 'tradewave/login.html'
        request_obj = {'status_msg': 'Your session has expired'}

    return render(request, template_name, request_obj)
