from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect
from django.template import RequestContext, loader
from django.views.generic import View, ListView, TemplateView

from tradewave.models import City, Venue, Entity, VenueMap, Credit, \
    Account, CreditMap, TradewaveUser, Relationship, Industry, Vendor, \
    Marketplace, Affiliation, TransactionLog, Product

from tradewave.serializers import AccountSerializer, TransactionLogSerializer
from tradewave.forms import AssignCreditToUserForm, CreateUserForm, MarketVenueDateForm
from tradewave.transaction import TradewaveTransaction
from tradewave.exceptions import CustomerInvalidCredentialsException

from collections import OrderedDict
from datetime import datetime, date, timedelta
from decimal import Decimal
from import_export import resources
from operator import attrgetter

from rest_framework import status
from rest_framework.decorators import api_view, APIView
from rest_framework.response import Response
from rest_framework import mixins
from rest_framework import generics
from rest_framework import permissions

from rest_pandas import PandasView

import time
import logging
import uuid


logging.basicConfig(level=logging.DEBUG, filename="log/views.log")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# *** API ***
class AccountList(generics.ListCreateAPIView):
    """
    List all accounts, or create a new account.
    """
    queryset = Account.objects.all()
    serializer_class = AccountSerializer


class AccountDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve / update / destroy an account.
    """
    queryset = Account.objects.all()
    serializer_class = AccountSerializer


# *** API ***
class TransactionLogList(generics.ListCreateAPIView):
    """
    List all accounts, or create a new transaction log.
    """
    queryset = TransactionLog.objects.all()
    serializer_class = TransactionLogSerializer


class TransactionLogDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve / update / destroy an account.
    """
    queryset = TransactionLog.objects.all()
    serializer_class = TransactionLogSerializer
    lookup_field = 'uuid'


class TransactionLogEntitySpentDetail(generics.ListAPIView):
    """
    Retrieve transactions for a given entity
    """
    serializer_class = TransactionLogSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    lookup_url_kwarg = "account_id"

    def get_queryset(self):
        account_id = self.kwargs.get(self.lookup_url_kwarg)
        transactions = TransactionLog.objects.filter(transact_from=account_id)

        before = self.request.query_params.get('before', None)
        if before:
            transactions = transactions.filter(
                date_transacted__lte=datetime.fromtimestamp(float(before))
            )

        after = self.request.query_params.get('after', None)
        if after:
            transactions = transactions.filter(
                date_transacted__gte=datetime.fromtimestamp(float(after))
            )
        return transactions


class TransactionLogEntityReceivedDetail(generics.ListAPIView):
    """
    Retrieve transactions for a given entity
    """
    serializer_class = TransactionLogSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    lookup_url_kwarg = "account_id"

    def get_queryset(self):
        account_id = self.kwargs.get(self.lookup_url_kwarg)
        transactions = TransactionLog.objects.filter(transact_to=account_id)

        before = self.request.query_params.get('before', None)
        if before:
            transactions = transactions.filter(
                date_transacted__lte=datetime.fromtimestamp(float(before))
            )

        after = self.request.query_params.get('after', None)
        if after:
            transactions = transactions.filter(
                date_transacted__gte=datetime.fromtimestamp(float(after))
            )
        return transactions


class TransactionLogEntitySpentPandas(PandasView):
    """
    Retrieve outgoing transactions for a given entity
    """
    serializer_class = TransactionLogSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    queryset = TransactionLog.objects.all()

    def filter_queryset(self, qs):
        account_id = self.kwargs.get('account_id')
        qs = TransactionLog.objects.filter(transact_from=account_id)
        before = self.request.query_params.get('before', None)
        if before:
            qs = qs.filter(
                date_transacted__lte=datetime.fromtimestamp(float(before))
            )

        after = self.request.query_params.get('after', None)
        if after:
            qs = qs.filter(
                date_transacted__gte=datetime.fromtimestamp(float(after))
            )
        return qs


class TransactionLogEntityReceiviedPandas(PandasView):
    """
    Retrieve incoming transactions for a given entity
    """
    serializer_class = TransactionLogSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    queryset = TransactionLog.objects.all()

    def filter_queryset(self, qs):
        account_id = self.kwargs.get('account_id')
        qs = TransactionLog.objects.filter(transact_to=account_id)
        before = self.request.query_params.get('before', None)
        if before:
            qs = qs.filter(
                date_transacted__lte=datetime.fromtimestamp(float(before))
            )

        after = self.request.query_params.get('after', None)
        if after:
            qs = qs.filter(
                date_transacted__gte=datetime.fromtimestamp(float(after))
            )
        return qs


# *** classes ***
class IndexView(ListView):
    model = User
    template_name = 'tradewave/index.html'


class SessionContextView(View):
    def get_context_data(self, **kwargs):
        context = super(SessionContextView, self).get_context_data(**kwargs)
        session = self.request.session
        state_vars = [
            'entity_id'
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


class LoginView(SessionContextView, TemplateView):
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


class CreateVendorView(SessionContextView, TemplateView):
    template_name = 'tradewave/create-vendor.html'

    def get_context_data(self, **kwargs):
        context = super(CreateVendorView, self).get_context_data(**kwargs)
        context['product_categories'] = [
            item.name for item in Product.objects.all()
        ]

        return context

class DashboardView(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super(DashboardView, self).get_context_data(**kwargs)
        if 'entity_marketplace' in context:
            context['entity_name'] = context['entity_marketplace']
        elif 'entity_vendor' in context:
            context['entity_name'] = context['entity_vendor']
        else:
            context['entity_name'] = context['entity_personal']

        context['market_venues'] = [
            venue.name
            for venue in Venue.objects.all()
        ]

        context['market_dates'] = [
            market_date.date() for market_date in TransactionLog.objects.datetimes(
                'date_transacted',
                'day'
            )
        ]

        context['credit_types'] = [
            credit.name for credit in Credit.objects.filter(issuer=context['entity_id'])
        ] + ['All']

        context['vendors'] = [
            vendor.name for vendor in Vendor.objects.all()
        ] + ['All']

        return context


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

            context['name'] = marketplace_entity.name

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


class MarketplaceIssueNew(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-issue-new.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceIssueNew, self).get_context_data(**kwargs)
        return context


class MarketplaceIssueLogin(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-issue-login.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceIssueLogin, self).get_context_data(**kwargs)
        return context


class MarketplaceIssuePickCredit(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-issue-pick-credit.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceIssuePickCredit, self).get_context_data(**kwargs)

        # List only marketplace's credits
        marketplace_account = Account.objects.get(id=context['account_entity_id'])
        marketplace_credits = dict([
            (str(creditmap.credit.uuid), creditmap.credit.name)
            for creditmap in marketplace_account.creditmap_set.all()
        ])
        context['marketplace_credits'] = marketplace_credits

        return context


class MarketplaceRedeem(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-redeem.html'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceRedeem, self).get_context_data(**kwargs)

        all_vendors = {}
        for vendor in Vendor.objects.all():
            vendor_account = vendor.account_set.first()
            if vendor_account and vendor_account.amount_total:
                all_vendors[vendor_account.id] = {
                    'name': vendor.name,
                    'amount_total': vendor_account.amount_total
                }

        context['all_vendors'] = all_vendors
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

        # applies any restrictions to a given credit
        def can_buy(credit):
            return (not credit.is_restricted) or credit.products.filter(
                id=context['product_category_id']
            )

        # generate the list of customer's credits
        cust_account = Account.objects.get(id=context['cust_account_personal_id'])
        cust_wallet = CreditMap.objects.filter(account=cust_account)
        cust_credits = OrderedDict([
            (entry.credit.uuid, {
                'name': entry.credit.name,
                'amount': float(entry.amount)
            })
            for entry in sorted(cust_wallet, key=attrgetter('amount'), reverse=True)
            if can_buy(entry.credit)
        ])

        logger.info(cust_credits)
        context['cust_credits'] = cust_credits
        context['tr_amount'] = float(context['tr_amount'])
        context['product_category'] = Product.objects.get(
            id=context['product_category_id']
        ).name

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

    class TransactionLogResource(resources.ModelResource):
        def get_queryset(self):
            form = MarketVenueDateForm(request.POST)

            if form.is_valid():
                market_date = form.cleaned_data['market_date']
                credit_type = form.cleaned_data['credit_type']
                vendor = form.cleaned_data['vendor']
                logger.info(
                    'Valid market data request for %s',
                    market_date
                )

                transactions = TransactionLog.objects.filter(
                    venue__name=form.cleaned_data['market_venue'],
                    date_transacted__gte=market_date,
                    date_transacted__lt=market_date + timedelta(days=1)
                )

                if credit_type != 'All':
                    transactions = transactions.filter(credit__name=credit_type)

                if vendor != 'All':
                    transactions = transactions.filter(transact_to__entity__name=vendor)

                return transactions
            else:
                logger.warning('Invalid request for transaction history: %s', form.errors.as_data())
                return None

        class Meta:
            model = TransactionLog
            fields = (
                'uuid',
                'transact_from__entity__name',
                'transact_to__entity__name',
                'credit__name',
                'amount',
                'venue__name',
                'date_transacted'
            )
            #exclude = ('id',)

    try:
        dataset = TransactionLogResource().export()
        response = HttpResponse(dataset.csv, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=tw-market-data-%s.csv'
        response['Content-Disposition'] %= datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        return response

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)


def login_username_or_qr(request):
    cust_name = request.POST.get('cust_name')
    cust_password = request.POST.get('cust_password')
    cust_qr_string = request.POST.get('cust_qr_string')
    cust_pin = request.POST.get('cust_pin')

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
            logger.info('Authenticated customer as [%s]', user.username)
        except Exception as e:
            status_msg = 'Invalid authentication attempt using QR'
            logger.warning(
                '%s: %s (%s)',
                status_msg,
                e.message,
                type(e)
            )
            raise Exception('Invalid QR credentials')

    # is existing active user?
    if user is not None and user.is_active:
        # return user object to the caller
        return user
    else:
        raise CustomerInvalidCredentialsException('Invalid credentials for customer')


# *** handler to process user login ***
def process_cust_login(request, login_reason):
    try:
        # athenticate customer within the master entity session
        user = login_username_or_qr(request)
        cust_twuser = user.tradewaveuser

        # customer's personal entity
        cust_personal_entity = cust_twuser.user_entity
        cust_name = user.username

        # set session-wide variable customer entity
        request.session['entity_customer'] = cust_name
        request.session['entity_customer_id'] = cust_personal_entity.id
        logger.info('customer entity name: %s', cust_personal_entity.name)

        # customers account data
        cust_account = cust_personal_entity.account_set.first()
        request.session['cust_account_personal_id'] = cust_account.id
        cust_amount_total = cust_account.amount_total
        request.session['cust_total'] = float(cust_amount_total)

        # common fields to all requests
        context_obj = {
            'cust_name': cust_name,
            'cust_total': float(cust_amount_total),
        }

        # login_reason determines if this customer login was requested
        # from transaction or issuing credits.
        logger.info('login_reason: %s', login_reason)

        # login requested from transaction flow
        if login_reason == 'transaction':
            redirect_view = 'tradewave:vendor-choose-payment'

        # login requested from marketplace issue credit flow
        elif login_reason == 'issue_credit':
            redirect_view = 'tradewave:marketplace-issue-pick-credit'

        else:
            status_msg = 'Unknown referrer'
            return redirect('tradewave:user-home-status', status_msg=status_msg)

        # TODO: evaluate any security risks here in storing everything in session
        #for key, val in context_obj.iteritems():
        #    request.session[key] = val

        return redirect(redirect_view);

    except CustomerInvalidCredentialsException as e:
        if login_reason == 'transaction':
            # TODO: This should redirect to a page that says invalid login, repeat
            return redirect('tradewave:vendor-transaction')
        elif login_reason == 'issue_credit':
            return redirect('tradewave:marketplace-issue-login')
        else:
            raise
    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:user-home-status', status_msg=e.message)


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
            is_vendor = user_tradewave.vendors.exists()
            is_marketplace = user_tradewave.marketplaces.exists()

            if is_vendor:
                user_entity = user_tradewave.vendors.first()
                request.session['entity_vendor'] = user_entity.name
                request.session['entity_id'] = user_entity.id
                logger.info('vendor entity name: %s', user_entity.name)

            # session-wide variable user marketplace entity
            # for simplicity only handle one-to-one user to marketplace association
            if is_marketplace:
                user_entity = user_tradewave.marketplaces.first()
                request.session['entity_marketplace'] = user_entity.name
                request.session['entity_id'] = user_entity.id
                logger.info('marketplace entity name: %s', user_entity.name)

            # generate the list of vendor / entity entity credits
            # we limit to a single account for simplicity for now
            if is_vendor or is_marketplace:
                entity_account = user_entity.account_set.first()
                entity_amount_total = entity_account.amount_total
                entity_wallet = entity_account.creditmap_set.all()
                entity_credits = OrderedDict([
                    (entry.credit.name, float(entry.amount))
                    for entry in sorted(entity_wallet, key=attrgetter('amount'), reverse=True)
                ])
                request.session['account_entity_id'] = entity_account.id

            if is_vendor:
                dest_url = 'vendor-initial'
            elif is_marketplace:
                dest_url = 'marketplace-initial'
            else:
                dest_url = 'user-home'

            return redirect('tradewave:%s' % dest_url)

        else:
            return redirect('tradewave:login', status_msg='Invalid email / password')

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)

# *** handler to process user logout ***
def process_logout(request):
    try:
        logout(request)
    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
    finally:
        return redirect('tradewave:login', status_msg='Please login to your account')


# *** handler for processing the payment from user to vendor ***
@login_required
@transaction.atomic
def process_vendor_payment(request):
    try:
        logger.info(request.POST.getlist('credits'))
        logger.info(request.POST.getlist('amounts'))
        credits = request.POST.getlist('credits')
        amounts = map(Decimal, request.POST.getlist('amounts'))
        tr_amount = float(request.POST.get('tr_amount'))

        sender_account_id = request.session['cust_account_personal_id']
        recipient_account_id = request.session['account_entity_id']
        sender_name=str(request.session['entity_customer'])
        recipient_name=str(request.session['entity_vendor'])

        tw_transaction = TradewaveTransaction(
            sender_account_id,
            recipient_account_id,
            venue_id=request.session['selected_venue_id']
        )

        # attempt to complete the user/vendor transaction as an atomic db transaction
        with transaction.atomic():
            for credit_uuid, amount in zip(credits, amounts):
                tr_credit = Credit.objects.get(uuid=credit_uuid)
                logger.info(
                    "Transaction from %s to %s in credit %s (%s) requested",
                    sender_name,
                    recipient_name,
                    tr_credit.name,
                    tr_credit.uuid
                )

                tw_transaction.transact(tr_credit.uuid, amount)

            return redirect(
                'tradewave:transaction-confirmed',
                tr_amount='%.2f' % tr_amount,
                amount='%.2f' % float(sum(amounts)),
                sender_name=sender_name,
                recipient_name=recipient_name,
                tr_type='vendor'
            )

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)

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
        request.session['tr_amount'] = product_amount

        return redirect('tradewave:vendor-cust-login', status_msg='')

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)

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
            return redirect(
                'tradewave:user-home-status',
                status_msg='Not associated to a vendor'
            )

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)


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
            logger.info('user has no marketplace associations')
            return redirect(
                'tradewave:user-home-status',
                status_msg='Not associated with a marketplace'
            )

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)


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
        status_msg ='Your session has expired. Please login again.'
        logger.warning(status_msg)
        return redirect('tradewave:login', status_msg=status_msg)


# *** handler to redirect to the marketplace page, if applicable ***
@login_required
def redeem_credits(request):
    try:
        selected_vendors = request.POST.getlist('vendors')
        amount_redeemed = 0

        for vendor_account_id in selected_vendors:
            logger.info(
                'Redeeming credits for vendor account id %s',
                vendor_account_id
            )
            tw_transaction = TradewaveTransaction(
                sender_account_id=vendor_account_id,
                recipient_account_id=request.session['account_entity_id'],
                venue_id=request.session['selected_venue_id']
            )

            with transaction.atomic():
                vendor_credits = CreditMap.objects.filter(account_id=vendor_account_id)
                for item in vendor_credits:
                    logger.info(
                        'Redeeming credit %s (%s)',
                        item.credit.name,
                        item.credit.uuid
                    )
                    tw_transaction.transact(
                        item.credit.uuid,
                        item.amount,
                        isRedeemed=True
                    )

                    amount_redeemed += tw_transaction.amount_last_transacted

        return redirect(
            'tradewave:transaction-confirmed',
            tr_amount='%.2f' % amount_redeemed,
            amount='%.2f' % amount_redeemed,
            sender_name='selected vendors',
            recipient_name=request.session['entity_marketplace'],
            tr_type='marketplace'
        )

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)


# *** handler for creating a new user ***
@login_required
@transaction.atomic
def create_user(request):
    try:
        form = CreateUserForm(request.POST)

        if form.is_valid():
            with transaction.atomic():
                user = User(
                    username=form.cleaned_data['user_email'],
                    email=form.cleaned_data['user_email'],
                    first_name=form.cleaned_data['user_firstname'],
                    last_name=form.cleaned_data['user_lastname']
                )
                user.set_password(form.cleaned_data['user_password'])
                user.save()
                logger.info('New user %s created', user.email)

                entity_personal = Entity(
                    name='Personal entity of %s' % user.email,
                    email=user.email
                )
                entity_personal.save()
                logger.info('%s created', entity_personal.name)

                tradewaveuser = TradewaveUser(
                    user=user,
                    user_entity=entity_personal,
                    pin=form.cleaned_data['user_pin'],
                    qr_string=str(uuid.uuid4())
                )
                tradewaveuser.save()
                logger.info('Tradewave user created for %s', user.email)

                user_account = Account(
                    entity=entity_personal,
                    amount_total=0
                )
                user_account.save()
                logger.info('Account created for %s', entity_personal.name)

                # TODO: this in essence is duplicating in part process_cust_login,
                # so consider using that here, even though it requires the credentials
                # to present in the request.
                request.session['cust_account_personal_id'] = user_account.id
                request.session['entity_customer'] = user.username
                request.session['entity_customer_id'] = user.id
                return redirect('tradewave:marketplace-issue-pick-credit')
        else:
            logger.error(
                'Invalid create user request: %s',
                form.errors.as_data()
            )

            # just report the first validation error
            errors = [
                '%s: %s' % (field, error)
                for field, le in form.errors.as_data().iteritems()
                for error in le
            ]
            return redirect('tradewave:marketplace-issue-new', status_msg=errors[0])

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)


# *** handler for creating a new user ***
@login_required
@transaction.atomic
def assign_credit_to_user(request):
    form = AssignCreditToUserForm(request.POST)

    if form.is_valid():
        data = form.cleaned_data
        tw_transaction = TradewaveTransaction(
            sender_account_id=request.session['account_entity_id'],
            recipient_account_id=request.session['cust_account_personal_id'],
            venue_id=request.session['selected_venue_id']
        )

        try:
            tw_transaction.transact(data['credit_uuid'], data['credit_amount'])

        except Exception as e:
            logger.error('Transaction error: %s (%s)', e.message, type(e))

        return redirect(
            'tradewave:transaction-confirmed',
            tr_amount='%.2f' % data['credit_amount'],
            amount='%.2f' % tw_transaction.amount_last_transacted,
            sender_name=str(request.session['entity_marketplace']),
            recipient_name=str(request.session['entity_customer']),
            tr_type='marketplace'
        )

    else:
        logger.error('Invalid form: %s', form.errors.as_data())
        return redirect('tradewave:marketplace-home')
