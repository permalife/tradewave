from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponse, HttpResponseNotFound
from django.shortcuts import render, redirect
from django.views.generic import View, ListView, TemplateView

from tradewave.models import \
    Venue, \
    TradewaveUser, \
    Entity, EntityVenues, \
    Vendor, \
    Marketplace, MarketplaceVendors, \
    Credit, Account, CreditMap, TransactionLog, \
    Product, \
    Token


from tradewave.forms import \
    AssignCreditToUserForm, \
    EntityInviteOrAssignUsersForm, \
    CreateUserForm, \
    CreateVendorForm, \
    DataExportForm, \
    LoginUserForm, \
    RedeemVendorsForm, \
    VendorTransactionForm, \
    VendorPaymentForm

from tradewave.allocations import CreditAllocations
from tradewave.exceptions import CustomerInvalidCredentialsException
from tradewave.serializers import AccountSerializer, TransactionLogSerializer
from tradewave.tasks import sendTransactionalEmail
from tradewave.token import TokenRecord
from tradewave.transaction import TradewaveTransaction
from tradewave.twuser import TwUser
from tradewave.wallet import Wallet

from collections import OrderedDict
from datetime import datetime, timedelta
from decimal import Decimal
from import_export import resources

from rest_framework import generics
from rest_framework import permissions

from rest_pandas import PandasView

import logging
import pytz
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


# *** class view ***
# Global session variables:
#   *) user_id
#   *) entity_id
#   *) entity_personal_id
#   *) entity_customer_id

# Known limitations:
#   1) A single account per entity type

class IndexView(ListView):
    model = User
    template_name = 'tradewave/index.html'


class SessionContextView(View):
    def get_context_data(self, **kwargs):
        context = super(SessionContextView, self).get_context_data(**kwargs)
        session = self.request.session

        # TODO: restric to items used in templates
        for key, val in session.iteritems():
            context[key] = val

        context['user_id'] = self.request.user.id
        return context


class LoginView(SessionContextView, TemplateView):
    template_name = 'tradewave/login.html'


class ErrorView(SessionContextView, TemplateView):
    template_name = 'tradewave/500.html'


class NotFoundView(SessionContextView, TemplateView):
    template_name = 'tradewave/404.html'


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


class TransactionConfirmedView(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/transaction-confirmed.html'
    permission_required = 'tradewave.can_transact'

    def get_context_data(self, **kwargs):
        context = super(TransactionConfirmedView, self).get_context_data(**kwargs)
        context['tr_amount'] = float(context['tr_amount'])
        context['amount'] = float(context['amount'])

        return context


# these should be some temporary users until they are confirmed
class CreateUser(SessionContextView, TemplateView):
    template_name = 'tradewave/create-user.html'


# anonymous requests with an invite token
class CreateUserNew(SessionContextView, TemplateView):
    template_name = 'tradewave/create-user.html'

    def get(self, request, *args, **kwargs):
        context = super(CreateUserNew, self).get_context_data(**kwargs)

        invite_token = context['invite_token']
        token_record = TokenRecord(invite_token)
        if token_record.is_valid():
            context['user_email'] = token_record.get_email()
            return render(request, self.template_name, context)
        else:
            error_msg = 'Invalid token: %s'
            logger.warning(error_msg, invite_token)
            return redirect(
                'tradewave:login',
                status_msg=error_msg % invite_token
            )


# anonymous request with a marketplace invite token
class CreateVendor(SessionContextView, TemplateView):
    template_name = 'tradewave/create-vendor.html'

    def get(self, request, *args, **kwargs):
        context = super(CreateVendor, self).get_context_data(**kwargs)

        invite_token = context['invite_token']
        token_record = TokenRecord(invite_token)
        marketplace = token_record.get_entity()

        if token_record.is_valid() and marketplace:
            context['marketplace_venues'] = dict([
                (item.id, item.name) for item in marketplace.venues.all()
            ])
            context['product_categories'] = dict([
                (item.id, item.name) for item in Product.objects.all()
            ])
            return render(request, self.template_name, context)
        else:
            error_msg = 'Invalid token: %s'
            logger.warning(error_msg, invite_token)
            return redirect(
                'tradewave:login',
                status_msg=error_msg % invite_token
            )


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

        # entity account id
        tw_user = TwUser(context['user_id'])
        wallet_entity = tw_user.get_entity_wallet()
        if wallet_entity:
            context['account_entity_id'] = wallet_entity.get_account_id()
        else:
            wallet_personal = tw_user.get_personal_wallet()
            context['account_entity_id'] = wallet_personal.get_account_id()

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

        # If user is associated to any other entity besides personal,
        # show the dashboard for that entity. Otherwise, show for personal entity.
        if 'entity_id' in context:
            credits = Credit.objects.filter(issuer=context['entity_id'])
        else:
            credits = Credit.objects.filter(issuer=context['entity_personal_id'])

        context['credit_types'] = [
            credit.name for credit in credits
        ] + ['All']

        context['vendors'] = [
            vendor.name for vendor in Vendor.objects.all()
        ] + ['All']

        return context


class MarketplaceInitial(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-initial.html'
    permission_required = 'tradewave.entity_marketplace'

    def get(self, request, *args, **kwargs):
        context = super(MarketplaceInitial, self).get_context_data(**kwargs)

        # retrieve tradewave user by django user id
        tw_user = TwUser(context['user_id'])
        user_name = tw_user.get_username()
        marketplace = tw_user.get_entity()

        if marketplace:
            self.request.session['entity_name'] = tw_user.get_entity_name()

            context['featured_venues'] = marketplace.venues.all()
            return render(request, self.template_name, context)
        else:
            error_msg = 'Must have a marketplace account (user %s)'
            logger.warning(error_msg, user_name)
            logout(request)
            return redirect(
                'tradewave:login',
                status_msg=error_msg % user_name
            )


class MarketplaceInviteVendors(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-invite-vendors.html'
    permission_required = 'tradewave.entity_marketplace'


class MarketplaceHome(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-home.html'
    permission_required = 'tradewave.entity_marketplace'


class MarketplaceIssue(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-issue.html'
    permission_required = 'tradewave.entity_marketplace'


class MarketplaceIssueLogin(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-issue-login.html'
    permission_required = 'tradewave.entity_marketplace'


class MarketplaceIssuePickCredit(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-issue-pick-credit.html'
    permission_required = 'tradewave.entity_marketplace'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceIssuePickCredit, self).get_context_data(**kwargs)

        # pass marketplace's credits
        wallet = Wallet(context['entity_id'])
        context['marketplace_credits'] = wallet.get_credit_names_by_uuid()

        return context


class MarketplaceRedeem(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/marketplace-redeem.html'
    permission_required = 'tradewave.entity_marketplace'

    def get_context_data(self, **kwargs):
        context = super(MarketplaceRedeem, self).get_context_data(**kwargs)

        marketplace_vendors = {}
        tw_user = TwUser(context['user_id'])
        marketplace = tw_user.get_entity()

        # pass all marketplace vendors that have a non-zero balance
        for vendor in marketplace.vendors.all():
            vendor_id = vendor.entity_ptr.id
            vendor_wallet = Wallet(vendor_id)
            amount_total = vendor_wallet.get_total()
            if amount_total:
                marketplace_vendors[vendor_id] = {
                    'name': vendor.name,
                    'amount_total': amount_total
                }

        context['marketplace_vendors'] = marketplace_vendors
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


class VendorChoosePayment(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-choose-payment.html'
    permission_required = ('tradewave.entity_vendor', 'tradewave.can_transact')

    def get(self, request, *args, **kwargs):
        context = super(VendorChoosePayment, self).get_context_data(**kwargs)

        # retrieve tradewave user by django user id
        tw_user = TwUser(context['user_id'])
        user_name = tw_user.get_username()

        if not tw_user.is_vendor():
            error_msg = 'User %s is not associated with any vendor'
            logger.error(error_msg, user_name)
            logout(request)
            return redirect(
                'tradewave:login',
                status_msg=error_msg % user_name
            )

        if not 'entity_customer_id' in context:
            error_msg = 'Customer must be logged in to make a transaction'
            logger.error(error_msg, user_name)
            return redirect(
                'tradewave:vendor-transaction',
                status_msg=error_msg % user_name
            )

        return render(request, self.template_name, context)


class VendorCustomerLogin(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-cust-login.html'
    permission_required = ('tradewave.entity_vendor', 'tradewave.can_transact')


class VendorHome(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-home.html'
    permission_required = 'tradewave.entity_vendor'

    def get_context_data(self, **kwargs):
        context = super(VendorHome, self).get_context_data(**kwargs)

        # retrieve tradewave user by django user id
        tw_user = TwUser(context['user_id'])
        vendor_wallet = tw_user.get_entity_wallet()

        # pass down the list of credits by name and the total amount
        context['credits'] = vendor_wallet.get_credit_amounts_by_name()
        context['total'] = vendor_wallet.get_total()

        return context


class VendorInitial(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-initial.html'
    permission_required = 'tradewave.entity_vendor'

    def get_context_data(self, **kwargs):
        context = super(VendorInitial, self).get_context_data(**kwargs)
        tw_user = TwUser(context['user_id'])
        vendor = tw_user.get_entity()
        marketplace = vendor.marketplace_set.first()
        logger.info(marketplace)
        self.request.session['entity_name'] = tw_user.get_entity_name()

        # pass down the list of marketplace venues the vendor belongs to
        context['featured_venues'] = marketplace.venues.all()

        return context


class VendorTransaction(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/vendor-transaction.html'
    permission_required = ('tradewave.entity_vendor', 'tradewave.can_transact')

    def get_context_data(self, **kwargs):
        context = super(VendorTransaction, self).get_context_data(**kwargs)
        tw_user = TwUser(context['user_id'])
        vendor = tw_user.get_entity()

        # pass down the list of product categories offered by the vendor
        context['product_categories'] = vendor.products.all()

        return context


class EntityInviteOrAssignUsers(LoginRequiredMixin, PermissionRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/entity-invite-or-assign-users.html'

    def has_permission(self):
        return self.request.user.has_perm('tradewave.entity_vendor') or self.request.user.has_perm('tradewave.entity_marketplace')

    def get_context_data(self, **kwargs):
        context = super(EntityInviteOrAssignUsers, self).get_context_data(**kwargs)
        tw_user = TwUser(context['user_id'])
        context['entity_name'] = tw_user.get_entity_name()

        return context


class UserHomeView(LoginRequiredMixin, SessionContextView, TemplateView):
    template_name = 'tradewave/user-home.html'

    def get_context_data(self, **kwargs):
        context = super(UserHomeView, self).get_context_data(**kwargs)

        # retrieve tradewave user by django user id
        tw_user = TwUser(context['user_id'])

        # generate the list of user personal credits
        wallet = tw_user.get_personal_wallet()

        # pass down the list of credits by name and the amount total
        context['total'] = wallet.get_total()
        context['credits'] = wallet.get_credit_amounts_by_name()

        return context


def compute_credit_allocations(request):
    transaction_data = request.session['transaction_data']
    vendor_id = request.session['entity_id']
    customer_id = request.session['entity_customer_id']

    allocations = CreditAllocations(
        transaction_data,
        vendor_id,
        customer_id
    )
    credit_data = allocations.compute()
    logger.info('Credit allocations: %s', credit_data)

    # we need to include credit names in addition to id's and amounts returned
    # by the allocator for the template to display those
    cust_transaction_credits = dict([
        (str(credit_id), {
            'name': Credit.objects.get(uuid=credit_id).name,
            'amount': credit_data[credit_id]
        })
        for credit_id in credit_data.keys()
    ])

    if credit_data:
        cust_transaction_total = sum(credit_data.values())
    else:
        cust_transaction_total = 0

    return {
        'cust_transaction_credits': cust_transaction_credits,
        'cust_transaction_total': cust_transaction_total
    }


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
            form = DataExportForm(request.POST)

            if form.is_valid():
                market_start_date = form.cleaned_data['market_start_date']
                market_end_date = form.cleaned_data['market_end_date']
                credit_type = form.cleaned_data['credit_type']
                vendor = form.cleaned_data['vendor']
                logger.info(
                    'Valid market data request between %s and %s',
                    market_start_date,
                    market_end_date
                )

                transactions = TransactionLog.objects.filter(
                    venue__name=form.cleaned_data['market_venue'],
                    date_transacted__gte=market_start_date,
                    date_transacted__lte=market_end_date
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

    try:
        dataset = TransactionLogResource().export()
        response = HttpResponse(dataset.csv, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=tw-market-data-%s.csv'
        response['Content-Disposition'] %= datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        return response

    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
        return redirect('tradewave:login', status_msg=e.message)


def login_username_or_qr(form_data):
    if form_data['login_qr']:
        try:
            user = TradewaveUser.objects.get(
                qr_string = form_data['user_qr_string'],
                pin = form_data['user_pin']
            )
        except:
            logger.warning(
                'Invalid qr login attempt: %s',
                form_data['user_qr_string']
            )
    else:
        user_name = form_data['user_name']
        user_password = form_data['user_password']
        user = authenticate(
            username=user_name,
            password=user_password
        )

    # is existing active user?
    if user is not None and user.is_active:
        logger.info(
            'Successful authentication: %s',
            user.username
        )
        # return user object to the caller
        return user
    else:
        if form_data['login_qr']:
            logger.warning(
                'Invalid authentication attempt using QR: %s',
                form_data['user_qr_string']
            )
        else:
            logger.warning(
                'Invalid authentication attempt using login/password: %s',
                form_data['user_name']
            )
        return None


# *** handler to process user login ***
def process_cust_login(request, login_reason):
    def redirect_back(login_reason, reject_reason):
        if login_reason == 'transaction':
            return redirect('tradewave:vendor-cust-login', reject_reason)
        elif login_reason == 'issue_credit':
            return redirect('tradewave:marketplace-issue-login', reject_reason)

    form = LoginUserForm(request.POST)

    if form.is_valid():
        # athenticate customer within the master entity session
        cust_user = login_username_or_qr(form.cleaned_data)
        if cust_user:
            cust_twuser = TwUser(cust_user.id)

            # customer's personal entity
            cust_personal_entity = cust_twuser.get_entity_personal()

            # set session-wide variable defining customer entity
            request.session['entity_customer'] = cust_twuser.get_username()
            request.session['entity_customer_id'] = cust_personal_entity.id
            logger.info('customer entity name: %s', cust_personal_entity.name)

            # login_reason determines if this customer login was requested
            # from transaction or issuing credits.
            logger.info('login_reason: %s', login_reason)

            # login requested from transaction flow
            if login_reason == 'transaction':
                cust_transaction_data = compute_credit_allocations(request)
                request.session['cust_transaction_credits'] = cust_transaction_data['cust_transaction_credits']
                request.session['cust_transaction_total'] = cust_transaction_data['cust_transaction_total']
                return redirect('tradewave:vendor-choose-payment')

            # login requested from marketplace issue credit flow
            elif login_reason == 'issue_credit':
                return redirect('tradewave:marketplace-issue-pick-credit')

        else:
            return redirect_back(
                login_reason,
                'Invalid login credentials'
            )

    # fail with form validation error
    else:
        logger.error(
            'Invalid customer login %s',
            form.errors.as_data()
        )

        # just report the first validation error
        errors = [
            '%s: %s' % (field, error)
            for field, le in form.errors.as_data().iteritems()
            for error in le
        ]
        return redirect_back(
            login_reason,
            status_msg=errors[0]
        )


# *** handler to process user login ***
def process_login(request):
    form = LoginUserForm(request.POST)

    if form.is_valid():
        user = login_username_or_qr(form.cleaned_data)
        if user is not None and user.is_active:
            login(request, user)
            logger.info('Successful login: %s', user.username)
            tw_user = TwUser(user.id)

            # user's personal entity
            user_personal_entity = tw_user.get_entity_personal()
            request.session['entity_personal'] = user_personal_entity.name
            request.session['entity_personal_id'] = user_personal_entity.id
            logger.info('personal entity name: %s', user_personal_entity.name)

            if tw_user.is_vendor():
                request.session['entity_vendor'] = tw_user.get_entity_name()
                dest_url = 'vendor-initial'
            elif tw_user.is_marketplace():
                request.session['entity_marketplace'] = tw_user.get_entity_name()
                dest_url = 'marketplace-initial'
            else:
                dest_url = 'user-home'

            if tw_user.is_vendor() or tw_user.is_marketplace():
                request.session['entity_id'] = tw_user.get_entity_id()
                logger.info('entity name: %s', tw_user.get_entity_name())

            return redirect('tradewave:%s' % dest_url)

        else:
            return redirect('tradewave:login', status_msg='Invalid email / password')

    # fail with form validation error
    else:
        logger.error(
            'Invalid login %s',
            form.errors.as_data()
        )

        # just report the first validation error
        errors = [
            '%s: %s' % (field, error)
            for field, le in form.errors.as_data().iteritems()
            for error in le
        ]
        return redirect('tradewave:login', status_msg=errors[0])


# *** handler to process user logout ***
@login_required
def process_logout(request):
    try:
        logout(request)
    except Exception as e:
        logger.error("Server error: %s (%s)", e.message, type(e))
    finally:
        return redirect('tradewave:login', status_msg='Please login to your account')


# *** handler to process user login ***
def process_signup(request):
    return redirect('tradewave:login', status_msg='Confirmation email sent')


# *** handler for processing the payment from user to vendor ***
@login_required
@permission_required('tradewave.entity_vendor')
@permission_required('tradewave.can_transact')
@transaction.atomic
def process_vendor_payment(request):
    form = VendorPaymentForm(request.POST)

    if form.is_valid():
        credit_uuids = form.cleaned_data['credit_uuids']
        credit_amounts = form.cleaned_data['credit_amounts']
        tr_amount = float(request.session['tr_amount'])

        wallet_vendor = Wallet(request.session['entity_id'])
        wallet_customer = Wallet(request.session['entity_customer_id'])
        sender_account_id = wallet_customer.get_account_id()
        recipient_account_id = wallet_vendor.get_account_id()
        sender_name = wallet_customer.get_entity_name()
        recipient_name = wallet_vendor.get_entity_name()

        tw_transaction = TradewaveTransaction(
            sender_account_id,
            recipient_account_id,
            venue_id=request.session['selected_venue_id']
        )

        with transaction.atomic():
            for credit_uuid, credit_amount in zip(credit_uuids, credit_amounts):
                tr_credit = Credit.objects.get(uuid=credit_uuid)
                logger.info(credit_uuid, credit_amount)
                # check if the amount is actually positive
                if credit_amount > 0:
                    logger.info(
                        "Transaction from %s to %s in credit %s (%s) requested",
                        sender_name,
                        recipient_name,
                        tr_credit.name,
                        tr_credit.uuid
                    )

                    tw_transaction.transact(tr_credit.uuid, credit_amount)
                else:
                    logger.info(
                        'Amount in credit %s (%s) is not a valid amount - no transaction executed',
                        tr_credit.name,
                        tr_credit.uuid
                    )
            return redirect(
                'tradewave:transaction-confirmed',
                tr_amount='%.2f' % tr_amount,
                amount='%.2f' % float(sum(credit_amounts)),
                sender_name=sender_name,
                recipient_name=recipient_name,
                tr_type='vendor'
            )

    # fail with form validation error
    else:
        logger.error(
            'Invalid transaction data: %s',
            form.errors.as_data()
        )

        # just report the first validation error
        errors = [
            '%s: %s' % (field, error)
            for field, le in form.errors.as_data().iteritems()
            for error in le
        ]
        return redirect('tradewave:vendor-transaction', status_msg=errors[0])


# *** handler for vendor transaction screen ***
@login_required
@permission_required('tradewave.entity_vendor')
@permission_required('tradewave.can_transact')
def process_vendor_transaction(request):
    form = VendorTransactionForm(request.POST)

    if form.is_valid():
        product_categories = form.cleaned_data['product_categories']
        product_amounts = form.cleaned_data['product_amounts']

        transaction_data = dict(zip(product_categories, product_amounts))

        request.session['transaction_data'] = transaction_data
        request.session['tr_amount'] = sum(product_amounts)
        logger.info('transaction_data: %s', transaction_data)
        logger.info('tr_amount: %s', sum(product_amounts))

        return redirect('tradewave:vendor-cust-login')

    # fail with form validation error
    else:
        logger.error(
            'Invalid transaction data: %s',
            form.errors.as_data()
        )

        # just report the first validation error
        errors = [
            '%s: %s' % (field, error)
            for field, le in form.errors.as_data().iteritems()
            for error in le
        ]
        return redirect('tradewave:vendor-transaction', status_msg=errors[0])


# *** handler to redirect to the vendor page, if applicable ***
@login_required
@permission_required('tradewave.entity_vendor')
def redirect_to_vendor(request):
    tw_user = TwUser(request.user.id)

    if tw_user.is_vendor():
        logger.info('user has a vendor association')
        if 'selected_venue' in request.session:
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


# *** handler to redirect to the marketplace page, if applicable ***
@login_required
@permission_required('tradewave.entity_marketplace')
def redirect_to_marketplace(request):
    tw_user = TwUser(request.user.id)

    if tw_user.is_marketplace():
        logger.info('user has a marketplace association')
        if 'selected_venue' in request.session:
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


# *** handlers [record] ***
@login_required
def record_venue(request, venue_id):
    logger.info("Selected venue id is [%s]", venue_id)
    venue = Venue.objects.get(id=venue_id)
    request.session['selected_venue'] = venue.name
    request.session['selected_venue_id'] = venue.id

    # determine the destination template
    if 'entity_vendor' in request.session:
        return redirect('tradewave:vendor-home')

    elif 'entity_marketplace' in request.session:
        return redirect('tradewave:marketplace-home')

    else:
        # possibly the session has expired, have the user re-login
        status_msg = 'Your session has expired. Please login again.'
        logger.warning(status_msg)
        return redirect('tradewave:login', status_msg=status_msg)


# *** handler to redirect to the marketplace page, if applicable ***
@login_required
@permission_required('tradewave.entity_marketplace')
@transaction.atomic
def redeem_credits(request):
    form = RedeemVendorsForm(request.POST)
    if form.is_valid():
        logger.info(form.cleaned_data)
        vendors = form.cleaned_data['vendors']
        marketplace_wallet = Wallet(form.cleaned_data['entity_marketplace_id'])
        marketplace_account_id = marketplace_wallet.get_account_id()
        amount_redeemed = 0

        for vendor_id in vendors:
            vendor_wallet = Wallet(vendor_id)
            vendor_account_id = vendor_wallet.get_account_id()
            logger.info(
                'Redeeming credits for vendor account id %s',
                vendor_account_id
            )
            tw_transaction = TradewaveTransaction(
                sender_account_id=vendor_account_id,
                recipient_account_id=marketplace_account_id,
                venue_id=request.session['selected_venue_id']
            )

            with transaction.atomic():
                vendor_credits = vendor_wallet.get_wallet()
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

        if len(vendors) > 1:
            vendors_name = 'selected vendors'
        elif len(vendors) == 1:
            vendor = Vendor.objects.get(id=vendors[0])
            vendors_name = vendor.name

        return redirect(
            'tradewave:transaction-confirmed',
            tr_amount='%.2f' % amount_redeemed,
            amount='%.2f' % amount_redeemed,
            sender_name=vendors_name,
            recipient_name=request.session['entity_marketplace'],
            tr_type='marketplace'
        )

    # fail with form validation error
    else:
        logger.error(
            'Invalid login %s',
            form.errors.as_data()
        )

        # just report the first validation error
        errors = [
            '%s: %s' % (field, error)
            for field, le in form.errors.as_data().iteritems()
            for error in le
        ]
        return redirect('tradewave:marketplace-redeem', status_msg=errors[0])


# *** view handler for creating a new user ***
# Describe all pathways this handler is called from:
#
#   1. Marketplace creates a new user to issue credits to
#       a. calling sequence: marketplace-issue => create-user
#       b. authentication: login_required
#       c. context (incoming): n/a
#       d. context (outgoing):
#           * cust_account_personal_id
#           * entity_customer
#           * entity_customer_id
#       e. redirect: marketplace-issue-pick-credit
#
#   2. New vendor flow (create vendor user account)
#       a. calling sequence: create-vendor => create-user
#       b. authentication: login_required
#       c. context (incoming):
#           * user_vendor_id
#           * user_vendor_name
#       d. context (outgoing):
#           * status_msg
#       e. redirect: marketplace-home
#
#   3. New user signing up with an invite code
#       a. calling sequence: direct request
#       b. authentication: none
#       c. context (incoming):
#           * user_invite_code
#       d. context (outgoing): n/a
#       e. redirect: login
@transaction.atomic
def create_user(request):
    form = CreateUserForm(request.POST)

    if form.is_valid():
        invite_token = form.cleaned_data['user_invite_code']
        if invite_token:
            logger.info('Request with invite token: %s', invite_token)
        else:
            logger.info('Request without an invite token')

            # authorization: must be a marketplace
            if not request.user.has_perm('tradewave.entity_marketplace'):
                return redirect(
                    'tradewave:login',
                    'Unauthorized request'
                )

        user_vendor_id = None
        user_marketplace_id = None

        # if pathway 3
        if invite_token:
            invite_record = TokenRecord(invite_token)

            # check this is a valid invite code
            if invite_record:
                logger.info(
                    'Invite record retrieved for token %s',
                    invite_token
                )

                if invite_token.is_valid():
                    logger.info('Invite token is valid')

                    # invite records may contain requested entity associations
                    vendor = invite_record.get_vendor()
                    if vendor:
                        user_vendor_id = vendor.id
                        logger.info(
                            'Vendor %s association requested',
                            vendor.name
                        )

                    marketplace = invite_record.get_marketplace()
                    if marketplace:
                        user_marketplace_id = marketplace.id
                        logger.info(
                            'Marketplace %s association requested',
                            marketplace.name
                        )

                else:
                    logger.warning('Invite token is no longer valid')
                    return redirect(
                        'tradewave:login',
                        status_msg='Invalid signup token'
                    )
            else:
                logger.warning(
                    'Invite record not found for token %s',
                    invite_token
                )
                return redirect(
                    'tradewave:login',
                    status_msg='Invalid signup token'
                )

        # proceed with creating the models now
        # TODO: refactor into function
        with transaction.atomic():
            user_name = form.cleaned_data['user_email']
            user_email = form.cleaned_data['user_email']
            user_firstname = form.cleaned_data['user_firstname']
            user_lastname = form.cleaned_data['user_lastname']
            user_password = form.cleaned_data['user_password']

            # record user_vendor_id in order to check for pathway 2 below
            if not user_vendor_id:
                user_vendor_id = form.cleaned_data['user_vendor_id']

            user = User(
                username=user_name,
                email=user_email,
                first_name=user_firstname,
                last_name=user_lastname
            )
            user.set_password(user_password)
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

            # create vendor association, if requested
            if user_vendor_id:
                user_vendor = Vendor.objects.get(id=user_vendor_id)
                tradewaveuser.vendors.add(user_vendor)
                tradewaveuser.save()
                logger.info(
                    'User %s is now linked to vendor entity %s',
                    user.email,
                    user_vendor.name
                )

            # create marketplace association, if requested
            if user_marketplace_id:
                user_marketplace = Marketplace.objects.get(id=user_marketplace_id)
                tradewaveuser.marketplaces.add(user_marketplace)
                tradewaveuser.save()
                logger.info(
                    'User %s is now linked to marketplace entity %s',
                    user.email,
                    user_marketplace.name
                )

            # pathway 3 redirect
            if invite_token:
                return redirect(
                    'tradewave:login',
                    status_msg='User successfully created'
                )
            # pathway 2 redirect
            elif user_vendor_id:
                return redirect(
                    'tradewave:marketplace-home-status',
                    status_msg=' '.join([
                        'User',
                        user.email,
                        'is now linked to vendor',
                        user_vendor.name
                    ])
                )
            # pathway 1 redirect
            else:
                # set customer sessions vars to conduct the transaction
                request.session['entity_customer'] = user.username
                request.session['entity_customer_id'] = tradewaveuser.user_entity_id
                return redirect('tradewave:marketplace-issue-pick-credit')

    # fail with form validation error
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

        if request.user.has_perm('tradewave.entity_marketplace'):
            return redirect('tradewave:marketplace-issue-new', status_msg=errors[0])
        else:
            return redirect('tradewave:login', status_msg=errors[0])


# *** handler for creating a new vendor ***
@transaction.atomic
def create_vendor(request, token):
    form = CreateVendorForm(request.POST)

    if form.is_valid():
        vendor_name = form.cleaned_data['vendor_name']
        vendor_email = form.cleaned_data['vendor_email']
        vendor_has_csa = form.cleaned_data['vendor_has_csa']
        vendor_product_categories = form.cleaned_data['vendor_product_categories']
        vendor_venues = form.cleaned_data['vendor_venues']
        marketplace = None

        # use the invite token to determine the association
        # TODO
        # create a function that validates the token and marks it as verified
        if token:
            # compare the invite code with the stored one
            try:
                token_record = Token.objects.get(
                    email=vendor_email,
                    token=token
                )

                if token_record.date_expires > datetime.now(pytz.utc):
                    marketplace = token_record.marketplace
                else:
                    warning_message = 'Token %s already expired'
                    logger.warning(warning_message, token)
                    return redirect(
                        'tradewave:login',
                        status_msg=warning_message
                    )
            except Exception as e:
                logger.info('%s (%s)', e.message, type(e))

        # associate vendor to the current marketplace
        elif request.session['entity_marketplace']:
            marketplace = Marketplace.objects.get(id=request.session['entity_id'])
        else:
            error_message = 'Not authorized to create vendors'
            logger.error(error_message)
            return redirect('tradewave:login', status_msg=error_message)

        with transaction.atomic():
            vendor = Vendor(
                name=vendor_name,
                email=vendor_email,
                has_csa=vendor_has_csa,
            )
            vendor.save()
            logger.info('New vendor %s created', vendor_name)

            # assign products to vendor
            for category_id in vendor_product_categories:
                product = Product.objects.get(id=category_id)
                vendor.products.add(product)
                logger.info(
                    'Vendor %s now offers product %s', vendor_name, product.name
                )

            # assign venues to vendor
            for venue_id in vendor_venues:
                venue = Venue.objects.get(id=venue_id)
                ev = EntityVenues(
                    entity=vendor,
                    venue=venue
                )
                ev.save()
                logger.info(
                    'Vendor %s is now affiliated with venue %s', vendor_name, venue.name
                )

            # create vendor account
            vendor_account = Account(entity=vendor, amount_total=0)
            vendor_account.save()
            logger.info('Account created for %s', vendor.name)

            # add vendor to the corresponding marketplace
            if marketplace:
                mv = MarketplaceVendors(
                    marketplace=marketplace,
                    vendor=vendor
                )
                mv.save()
                logger.info(
                    'Vendor %s is now a member of marketplace %s',
                    vendor_name,
                    marketplace.name
                )

            return redirect(
                'tradewave:create-user-vendor',
                vendor_id=vendor.id,
                vendor_name=vendor.name,
                status_msg=' '.join([
                    'Create your personal account to join',
                    vendor_name,
                    'organization'
                ])
            )

    else:
        logger.error(
            'Invalid create vendor request: %s',
            form.errors.as_data()
        )

        # just report the first validation error
        errors = [
            '%s: %s' % (field, error)
            for field, le in form.errors.as_data().iteritems()
            for error in le
        ]
        return redirect(
            'tradewave:create-vendor',
            invite_token=request.POST['vendor_invite_code'],
            status_msg=errors[0]
        )


# *** handler for creating a new user ***
@login_required
@transaction.atomic
def assign_credit_to_user(request):
    form = AssignCreditToUserForm(request.POST)

    if form.is_valid():
        marketplace_wallet = Wallet(request.session['entity_id'])
        customer_wallet = Wallet(request.session['entity_customer_id'])

        transaction = TradewaveTransaction(
            sender_account_id=marketplace_wallet.get_account_id(),
            recipient_account_id=customer_wallet.get_account_id(),
            venue_id=request.session['selected_venue_id']
        )

        data = form.cleaned_data
        try:
            transaction.transact(data['credit_uuid'], data['credit_amount'])

        except Exception as e:
            logger.error('Transaction error: %s (%s)', e.message, type(e))
            return redirect(
                'tradewave:marketplace-home',
                status_msg='Transaction did not succeed'
            )

        return redirect(
            'tradewave:transaction-confirmed',
            tr_amount='%.2f' % data['credit_amount'],
            amount='%.2f' % transaction.amount_last_transacted,
            sender_name=str(request.session['entity_marketplace']),
            recipient_name=str(request.session['entity_customer']),
            tr_type='marketplace'
        )

    else:
        logger.error('Invalid form: %s', form.errors.as_data())
        return redirect('tradewave:marketplace-home')


# *** view handler for assigning users to vendor ***
@login_required
@transaction.atomic
def entity_invite_or_assign_users(request, entity_id, is_vendor):
    entity = Entity.objects.get(id=entity_id)
    entity_type = None
    entity_to_assign = None
    try:
        entity_to_assign = entity.vendor
        entity_type = 'Vendor'
    except Exception:
        pass

    try:
        entity_to_assign = entity.marketplace
        entity_type = 'Marketplace'
    except Exception:
        pass

    if not entity_type:
        warning_message = 'Request for invalid entity: %s'
        logger.warning(warning_message, entity_id)
        return redirect(
            'tradewave:user-home-status',
            status_msg=warning_message % entity_id
        )
    else:
        logger.info('Entity is a %s', entity_type.lower())

    form = EntityInviteOrAssignUsersForm(request.POST)
    if form.is_valid():
        data = form.cleaned_data
        user_emails = data['user_emails']

        for user_email in user_emails:
            logger.info(
                'Request to assign user %s to entity %s',
                user_email,
                entity.name
            )

            # existing user
            if TradewaveUser.objects.filter(user__email=user_email):
                twuser = TradewaveUser.objects.get(user__email=user_email)
                if entity_type == 'Vendor':
                    twuser.vendors.add(entity_to_assign)
                elif entity_type == 'Marketplace':
                    twuser.marketplaces.add(entity_to_assign)
                twuser.save()
                logger.info(
                    'Assigned existing user %s to entity %s',
                    twuser.user.email,
                    entity.name
                )

            # new user
            else:
                # generate and store the token
                token = uuid.uuid4()
                one_week_from_now = datetime.now() + timedelta(days=7)

                token_type = None
                if entity_type == 'Vendor':
                    token_type = 'entity-invite-user'
                    token_record = Token(
                        email=user_email,
                        token=token,
                        token_type=token_type,
                        vendor=entity.vendor,
                        is_vendor=is_vendor,
                        date_expires=one_week_from_now
                    )
                elif entity_type == 'Marketplace':
                    if is_vendor:
                        token_type = 'marketplace-invite-vendor'
                    else:
                        token_type = 'entity-invite-user'

                    token_record = Token(
                        email=user_email,
                        token=token,
                        token_type=token_type,
                        marketplace=entity.marketplace,
                        is_vendor=is_vendor,
                        date_expires=one_week_from_now
                    )

                token_record.save()
                logger.info('Created new token of type %s', token_type)

                # send an email to the prospective user asking to join
                sendTransactionalEmail.apply_async(
                    [
                        token_type,
                        None,
                        [
                            {
                                'name': 'ENTITY_NAME',
                                'content': entity.name
                            },
                            {
                                'name': 'ENTITY_TYPE',
                                'content': entity_type
                            },
                            {
                                'name': 'TOKEN',
                                'content': token
                            }
                        ],
                        user_email,
                        'Join %s %s on Tradewave' % (
                            entity_type.lower(),
                            entity.name
                        )
                    ],
                    expires=one_week_from_now
                )

        status_msg = 'Invite email%s have been sent out to the '
        num_emails = len(user_emails)

        if num_emails > 1:
            status_msg %= 's'
            status_msg += '%d specified addresses' % num_emails
        else:
            status_msg %= ''
            status_msg += 'specified address'
        return redirect(
            'tradewave:%s-home-status' % entity_type.lower(),
            status_msg=status_msg
        )
    else:
        logger.error('Invalid form: %s', form.errors.as_data())
        return redirect('tradewave:%s-home' % entity_type.lower())


def process_invite(request, token):
    if Token.objects.filter(token=token):
        logger.info('Verification record found for token %s', token)
        token_record = Token.objects.get(token=token)
        if token_record.date_expires > datetime.now(pytz.utc):
            token_record.is_verified = True
            return redirect('tradewave:create-user')
        else:
            logger.warning('Token %s has already expired', token)
            return redirect('tradewave:login')


def return_404(request):
    return HttpResponseNotFound('Not found')
