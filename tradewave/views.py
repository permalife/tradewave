from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.template import RequestContext, loader
from django.views.generic import View, ListView, TemplateView


from tradewave.models import City, Venue, Entity, VenueMap, Credit, \
    Account, CreditMap, TradewaveUser, Relationship, Industry, Vendor, \
    Marketplace, Affiliation, TransactionLog, Product

from collections import OrderedDict
from datetime import datetime
from decimal import Decimal
from import_export import resources
from operator import attrgetter

import time
import logging


logging.basicConfig(level=logging.DEBUG, filename="log/views.log")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# *** classes ***
class IndexView(ListView):
    model = User
    template_name = 'tradewave/index.html'


class SessionContextView(View):
    def get_context_data(self, **kwargs):
        context = super(SessionContextView, self).get_context_data(**kwargs)
        session = self.request.session
        state_vars = [
            'entity_personal',
            'entity_vendor',
            'entity_customer',
            'entity_marketplace',
            'product_category',
            'selected_venue'
        ]

        #for var in state_vars:
        #    if session.has_key(var):
        #        context[var] = session[var]

        # TODO: revisit any potential security risks here
        for key, val in session.iteritems():
            context[key] = val

        context['user_id'] = self.request.user.id
        return context


class LoginView(ListView):
    model = User
    template_name = 'tradewave/login.html'


class SendView(ListView):
    model = User
    template_name = 'tradewave/send.html'


class ConfirmSendView(ListView):
    model = User
    template_name = 'tradewave/confirm-send.html'


class ConfirmReceiveView(ListView):
    model = User
    template_name = 'tradewave/confirm-receive.html'


class CustomerSupportView(SessionContextView, TemplateView):
    template_name = 'tradewave/cust-support.html'


class TransactionConfirmedView(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/transaction-confirmed.html'

    def get_context_data(self, **kwargs):
        context = super(TransactionConfirmedView, self).get_context_data(**kwargs)
        context['tr_amount'] = float(context['tr_amount'])
        context['amount'] = float(context['amount'])

        return context


class CreateUserView(ListView):
    model = User
    template_name = 'tradewave/create-user.html'


class CreateVendorView(ListView):
    model = User
    template_name = 'tradewave/create-vendor.html'

class DashboardView(LoginRequiredMixin, SessionContextView, ListView):
    model = User
    template_name = 'tradewave/dashboard.html'


class LoadDdipView(ListView):
    model = User
    template_name = 'tradewave/load-ddip.html'


class MarketplaceInitial(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-initial.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceInitial, self).get_context_data(**kwargs)
        context['featured_venues'] = Venue.objects.all()
        return context


class MarketplaceHome(LoginRequiredMixin, SessionContextView, TemplateView):
    # url args: user_id (django user id)
    template_name = 'tradewave/marketplace-home.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceHome, self).get_context_data(**kwargs)

        # retrieve tradewave user by django user id
        tw_user = TradewaveUser.objects.get(user_id=context['user_id'])
        user_name = tw_user.user.username

        # do basic authorization check by user_name here
        # TODO: use django permissions
        if user_name != self.request.user.username:
            raise PermissionDenied('Not authorized to access this page')

        if tw_user.marketplaces.exists():
            # user's personal entity
            marketplace_entity = tw_user.marketplaces.first()
            logger.info('marketplace entity: %s', marketplace_entity.name)

            # generate marketplace's credit account statement
            # we limit to a single account for simplicity for now
            marketplace_account = marketplace_entity.account_set.first()
            self.request.session['account_entity_id'] = marketplace_account.id
            marketplace_amount_total = marketplace_account.amount_total
            marketplace_wallet = CreditMap.objects.filter(account=marketplace_account)
            marketplace_credits = OrderedDict([
                (entry.credit.name, float(entry.amount))
                for entry in sorted(marketplace_wallet, key=attrgetter('amount'), reverse=True)
            ])
            logger.info(marketplace_credits)

            context['name'] = marketplace_entity.name
            context['total'] = marketplace_amount_total
            context['credits'] = marketplace_credits

        else:
            logger.warning(
                'User %s is not associated with any marketplace',
                user_name
            )

        logger.info(context)
        return context


class MarketplaceIssue(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-issue.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceIssue, self).get_context_data(**kwargs)
        return context


class MarketplaceRedeem(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-redeem.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceRedeem, self).get_context_data(**kwargs)
        return context


class MarketplaceSend(ListView):
    model = User
    template_name = 'tradewave/marketplace-send.html'


class SettingsUser(ListView):
    model = User
    template_name = 'tradewave/settings-user.html'


class SettingsVendor(ListView):
    model = User
    template_name = 'tradewave/settings-vendor.html'


class SettingsMarketplace(ListView):
    model = User
    template_name = 'tradewave/settings-marketplace.html'


class VendorChoosePayment(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-choose-payment.html'

    def get_context_data(self, **kwargs):
        context = super(VendorChoosePayment, self).get_context_data(**kwargs)
        logger.info(context)

        # retrieve tradewave user by django user id
        tw_user = TradewaveUser.objects.get(user_id=context['user_id'])
        user_name = tw_user.user.username

        # user's personal entity
        user_personal_entity = tw_user.user_entity
        logger.info('user\'s personal entity: %s', user_personal_entity.name)

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

        context['user_name'] = user_name
        context['user_total'] = user_amount_total
        context['user_credits'] = user_credits
        context['tr_amount'] = float(context['tr_amount'])

        return context

class VendorCustLogin(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-cust-login.html'

    def get_context_data(self, **kwargs):
        context = super(VendorCustLogin, self).get_context_data(**kwargs)
        return context


class VendorHome(LoginRequiredMixin, SessionContextView, TemplateView):
    # url args: user_id (django user id)
    template_name = 'tradewave/vendor-home.html'

    def get_context_data(self, **kwargs):
        context = super(VendorHome, self).get_context_data(**kwargs)

        # retrieve tradewave user by django user id
        tw_user = TradewaveUser.objects.get(user_id=context['user_id'])
        user_name = tw_user.user.username

        # do basic authorization check by user_name here
        # TODO: use django permissions
        if user_name != self.request.user.username:
            raise PermissionDenied('Not authorized to access this page')

        if tw_user.vendors.exists():
            # user's vendor entity
            vendor_entity = tw_user.vendors.first()
            logger.info('vendor entity: %s', vendor_entity.name)

            # generate vendor's credit account statement
            # we limit to a single account for simplicity for now
            vendor_account = vendor_entity.account_set.first()
            self.request.session['account_entity_id'] = vendor_account.id
            vendor_amount_total = vendor_account.amount_total
            vendor_wallet = CreditMap.objects.filter(account=vendor_account)
            vendor_credits = OrderedDict([
                (entry.credit.name, float(entry.amount))
                for entry in sorted(vendor_wallet, key=attrgetter('amount'), reverse=True)
            ])
            logger.info(vendor_credits)

            context['name'] = vendor_entity.name
            context['total'] = vendor_amount_total
            context['credits'] = vendor_credits

        else:
            logger.warning(
                'User %s is not associated with any vendor',
                user_name
            )

        logger.info(context)
        return context


class VendorInitial(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-initial.html'

    def get_context_data(self, **kwargs):
        context = super(VendorInitial, self).get_context_data(**kwargs)
        context['featured_venues'] = Venue.objects.all()
        return context


class VendorTransaction(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-transaction.html'

    def get_context_data(self, **kwargs):
        context = super(VendorTransaction, self).get_context_data(**kwargs)
        context['product_categories'] = Product.objects.all()
        return context


class UserHomeView(LoginRequiredMixin, SessionContextView, TemplateView):
    # url args: user_id (django user id)
    template_name = 'tradewave/user-home.html'

    def get_context_data(self, **kwargs):
        context = super(UserHomeView, self).get_context_data(**kwargs)

        # retrieve tradewave user by django user id
        tw_user = TradewaveUser.objects.get(user_id=context['user_id'])
        user_name = tw_user.user.username

        # do basic authorization check by user_name here
        # TODO: use django permissions
        if user_name != self.request.user.username:
            raise PermissionDenied('Not authorized to access this page')

        # user's personal entity
        user_personal_entity = tw_user.user_entity
        logger.info('user\'s personal entity: %s', user_personal_entity.name)

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

        context['name'] = user_name
        context['user_total'] = user_amount_total
        context['user_credits'] = user_credits

        return context


# *** handler for completing the transaction vendor-user transaction ***
def export_data(request):
    class CreditMapResource(resources.ModelResource):

        class Meta:
            model = CreditMap
            fields = (
                'account__entity__name',
                'credit__name',
                'amount',
                'account__date_last_transacted'
            )
            exclude = ('id',)

    try:
        dataset = CreditMapResource().export()
        response = HttpResponse(dataset.csv, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=tw-account-data-%s.csv'
        response['Content-Disposition'] %= datetime.now().strftime('%Y-%M-%d-%H-%M-%S')
        return response

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {
            'status_msg': 'Server error occured, we were notified!'
        }
        return render(request, 'tradewave/login.html', context_obj)


# *** handler to process user login ***
def process_cust_login(request):
    try:
        # TODO: use django forms
        cust_name = request.POST.get('cust_name')
        cust_password = request.POST.get('cust_password')
        cust_qr_string = request.POST.get('cust_qr_string')
        cust_pin = request.POST.get('cust_pin')
        tr_amount = request.POST.get('tr_amount')

        user = None
        if cust_name and cust_password:
            # login user django user credentials
            user = authenticate(
                username=cust_name,
                password=cust_password
            )
        elif cust_qr_string and cust_pin:
            # login using qr and pin
            try:
                cust_twuser = TradewaveUser.objects.get(
                    qr_string=cust_qr_string,
                    pin=cust_pin
                )
                user = cust_twuser.user
                logger.info('Logged in as [%s]', user.username)
            except Exception as e:
                logger.warning(
                    'Invalid login attempt using QR: %s (%s)',
                    e.message,
                    type(e)
                )
                return redirect('tradewave:vendor-cust-login', tr_amount=tr_amount)

        # is existing user?
        if user is not None and user.is_active:
            cust_twuser = user.tradewaveuser

            # user's personal entity
            cust_personal_entity = cust_twuser.user_entity
            cust_name = user.username

            # session-wide variable customer entity
            request.session['entity_customer'] = cust_name
            request.session['entity_customer_id'] = cust_personal_entity.id
            logger.info('customer entity name: %s', cust_personal_entity.name)

            # generate the list of customer credits
            # we limit to a single account for simplicity for now
            def can_buy(credit):
                return (not credit.is_restricted) or credit.products.filter(id=request.session['product_category_id'])

            cust_account = cust_personal_entity.account_set.first()
            request.session['cust_account_personal_id'] = cust_account.id
            cust_amount_total = cust_account.amount_total
            cust_wallet = CreditMap.objects.filter(account=cust_account)
            cust_credits = OrderedDict([
                (entry.credit.name, float(entry.amount))
                for entry in sorted(cust_wallet, key=attrgetter('amount'), reverse=True)
                if can_buy(entry.credit)
            ])
            logger.info(cust_credits)
            request.session['cust_total'] = float(cust_amount_total)
            request.session['cust_credits'] = cust_credits

            context_obj = {
                'vendor_name': request.session['entity_vendor'],
                'cust_name': cust_name,
                'cust_total': float(cust_amount_total),
                'cust_credits': cust_credits,
                'tr_amount': float(tr_amount),
                'product_category': Product.objects.get(
                    id=request.session['product_category_id']).name
            }

            for key, val in context_obj.iteritems():
                request.session[key] = val
            #return render(
            #    request,
            #    'tradewave/vendor-choose-payment.html',
            #    context_obj
            #)
            return redirect('tradewave:vendor-choose-payment');
        else:
            context_obj = {'status_msg': 'Invalid login / password'}
            return redirect('tradewave:vendor-cust-login', tr_amount=tr_amount)

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {
            'status_msg': 'Server error occured, we were notified!'
        }
        return render(request, 'tradewave/login.html', context_obj)


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

            # user's personal entity
            user_personal_entity = user.tradewaveuser.user_entity

            # session-wide variable user personal entity
            # (save it user_name for now because we use it for page title)
            request.session['entity_personal'] = user_name
            request.session['entity_personal_id'] = user_personal_entity.id
            logger.info('personal entity name: %s', user_personal_entity.name)

            # generate the list of user personal credits
            # we limit to a single account for simplicity for now
            user_account = user_personal_entity.account_set.first()
            request.session['account_personal_id'] = user_account.id
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
                request.session['entity_vendor_id'] = user_entity.id
                logger.info('vendor entity name: %s', user_entity.name)

            # session-wide variable user marketplace entity
            # for simplicity only handle one-to-one user to marketplace association
            if user_tradewave.marketplaces.exists():
                user_entity = user_tradewave.marketplaces.first()
                request.session['entity_marketplace'] = user_entity.name
                request.session['entity_marketplace_id'] = user_entity.id
                logger.info('marketplace entity name: %s', user_entity.name)

            # generate the list of vendor / entity entity credits
            # we limit to a single account for simplicity for now
            if user_tradewave.vendors.exists() or user_tradewave.marketplaces.exists():
                entity_account = user_entity.account_set.first()
                entity_amount_total = entity_account.amount_total
                entity_wallet = entity_account.creditmap_set.all()
                entity_credits = OrderedDict([
                    (entry.credit.name, float(entry.amount))
                    for entry in sorted(entity_wallet, key=attrgetter('amount'), reverse=True)
                ])
                #request.session['entity_total'] = float(entity_amount_total)
                #request.session['entity_credits'] = entity_credits

            return redirect('tradewave:user-home')

        else:
            context_obj = {'status_msg': 'Invalid login / password'}
            return render(request, 'tradewave/login.html', context_obj)

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {
            'status_msg': 'Server error occured, we were notified!'
        }
        return render(request, 'tradewave/login.html', context_obj)


# *** handler to process user logout ***
def process_logout(request):
    try:
        logout(request)
    except Exception as e:
        logger.error("Server error: %s", e)
    finally:
        context_obj = {'status_msg': 'Please login to your account'}
        return render(request, 'tradewave/login.html', context_obj)


# *** handler for processing the payment from user to vendor ***
@login_required
@transaction.atomic
def process_vendor_payment(request):
    try:
        logger.info(request.POST.getlist('credits'))
        logger.info(request.POST.getlist('amounts'))
        credits = request.POST.getlist('credits')
        amounts = request.POST.getlist('amounts')
        tr_amount = float(request.POST.get('tr_amount'))

        user_account = Account.objects.get(id=request.session['cust_account_personal_id'])
        entity_account = Account.objects.get(id=request.session['account_entity_id'])
        amounts = map(Decimal, amounts)

        # attempt to complete the user/vendor transaction as an atomic db transaction
        with transaction.atomic():
            for credit, amount in zip(credits, amounts):
                tr_credit = Credit.objects.get(name=credit)
                logger.info(tr_credit.uuid)

                # update or delete the asset for this credit in the user's wallet
                user_creditmap = user_account.creditmap_set.get(credit_id=tr_credit.uuid)
                if user_creditmap.amount > amount:
                    user_creditmap.amount -= amount
                    user_creditmap.save()
                    logger.info(' '.join([
                        'Account asset for credit',
                        tr_credit.name,
                        'was updated for user',
                        request.session['entity_customer']
                    ]))
                else:
                    user_creditmap.delete()
                    logger.info(' '.join([
                        'Account asset for credit',
                        tr_credit.name,
                        'was deleted for user',
                        request.session['entity_customer']
                    ]))

                # create or update the asset for this credit in the entity's wallet
                entity_creditmap, wasCreated = entity_account.creditmap_set.get_or_create(
                    credit_id=tr_credit.uuid,
                    defaults = {
                        'amount': amount
                    }
                )
                if wasCreated:
                    logger.info(' '.join([
                        'Account asset for credit',
                        tr_credit.name,
                        'was created for vendor',
                        request.session['entity_vendor']
                    ]))
                else:
                    entity_creditmap.amount += amount
                    entity_creditmap.save()
                    logger.info(' '.join([
                        'Account asset for credit',
                        tr_credit.name,
                        'was updated for vendor',
                        request.session['entity_vendor']
                    ]))

                # update transaction log
                tr_log = TransactionLog(
                    transact_from=user_account,
                    transact_to=entity_account,
                    credit=tr_credit,
                    amount=amount,
                    venue=Venue.objects.get(id=request.session['selected_venue_id']),
                    redeemed=False
                )
                tr_log.save()
                logger.info(' '.join([
                    'Credit:',
                    tr_credit.name,
                    'transaction log entry was created'
                ]))

                # account total records
                # (we'll save these at the end in a single db transaction)
                user_account.amount_total -= amount
                entity_account.amount_total += amount

            # save the changes to account totals
            user_account.save()
            entity_account.save()

            return redirect(
                'tradewave:transaction-confirmed',
                tr_amount='%.2f' % tr_amount,
                amount='%.2f' % float(sum(amounts))
            )

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {
            'status_msg': 'Server error occured, we were notified!'
        }
        return render(request, 'tradewave/login.html', context_obj)


# *** handler for vendor transaction screen ***
@login_required
def process_vendor_transaction(request):
    try:
        # TODO'S:
        #   use django forms
        #   track product categories
        product_category_id = request.POST.get('product_category_id')
        product_amount = float(request.POST.get('product_amount'))
        request.session['product_category_id'] = product_category_id

        return redirect(
            'tradewave:vendor-cust-login',
            tr_amount='%.2f' % product_amount
        )

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {'status_msg': e.message}
        return render(request, 'tradewave/login.html', context_obj)


# *** handler to redirect to the vendor page, if applicable ***
@login_required
def redirect_to_vendor(request):
    try:
        if request.session.has_key('entity_vendor'):
            logger.info('user has a vendor association')
            if request.session.has_key('selected_venue'):
                logger.info(
                    'user has already chosen a venue: %s',
                    request.session['selected_venue']
                )
                return redirect('tradewave:vendor-home')

            else:
                logger.info('user has not chosen a venue')
                return redirect('tradewave:vendor-initial')

        else:
            logger.info('user has no vendor associations')
            return redirect('tradewave:user-home')

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {
            'status_msg': 'Server error occurred: we were notified!'
        }
        return render(request, 'tradewave/login.html', context_obj)


# *** handler to redirect to the marketplace page, if applicable ***
@login_required
def redirect_to_marketplace(request):
    try:
        if request.session.has_key('entity_marketplace'):
            logger.info('user has a marketplace association')
            if request.session.has_key('selected_venue'):
                logger.info(
                    'user has already chosen a venue: %s',
                    request.session['selected_venue']
                )
                return redirect('tradewave:marketplace-home')
            else:
                logger.info('user has not chosen a venue')
                return redirect('tradewave:marketplace-initial')
        else:
            return redirect('tradewave:user-home')

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {
            'status_msg': 'Server error occurred: we were notified!'
        }
        return render(request, 'tradewave/login.html', context_obj)


# *** handlers [record] ***
@login_required
def record_venue(request, venue_id):
    logger.info("Selected venue id is [%s]", venue_id)
    venue = Venue.objects.get(id=venue_id)
    request.session['selected_venue'] = venue.name
    request.session['selected_venue_id'] = venue.id

    # determine the destination template
    if request.session.has_key('entity_vendor'):
        return redirect('tradewave:vendor-home')

    elif request.session.has_key('entity_marketplace'):
        return redirect('tradewave:marketplace-home')

    else:
        # possibly the session has expired, have the user re-login
        template_name = 'tradewave/login.html'
        context_obj = {'status_msg': 'Your session has expired'}
        return render(request, template_name, context_obj)

# *** handler for vendor transaction screen ***
@login_required
def process_user_create(request):
    try:
        # TODO'S:
        #   use django forms
        #   track product categories
        user_firstname = request.POST.get('user_firstname')
        user_lastname = request.POST.get('user_lastname')
        user_email = request.POST.get('user_email')
        user_password = request.POST.get('user_password')

        user = User(
            username=user_email,
            email=user_email,
            first_name=user_firstname,
            last_name=user_lastname
        )
        user.set_password(user_password)
        user.save()

        return redirect(
            'tradewave:marketplace-issue'
            #tr_amount='%.2f' % product_amount
        )

    except Exception as e:
        logger.error("Server error: %s", e)
        context_obj = {'status_msg': e.message}
        return render(request, 'tradewave/login.html', context_obj)
