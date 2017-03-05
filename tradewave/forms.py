from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _

from tradewave.models import \
    Credit, \
    Entity, \
    Marketplace, \
    Product, \
    TradewaveUser, \
    Venue

from datetime import datetime
from decimal import Decimal

import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class NotValidatedMultipleChoiceField(forms.TypedMultipleChoiceField):
    """Field that do not validate if the field values are in self.choices"""

    def to_python(self, value):
        """Override checking method"""
        return map(self.coerce, value)

    def validate(self, value):
        """Nothing to do here"""
        pass


# Create new user form
class CreateUserForm(forms.Form):
    user_firstname = forms.CharField()
    user_lastname = forms.CharField()
    user_email = forms.EmailField()
    user_password = forms.CharField(min_length=8)
    user_password_confirm = forms.CharField(min_length=8)
    user_pin = forms.IntegerField(min_value=1000, max_value=9999)
    user_pin_confirm = forms.IntegerField(min_value=1000, max_value=9999)
    user_vendor_id = forms.IntegerField(required=False)
    user_vendor_name = forms.CharField(required=False)
    user_invite_code = forms.UUIDField(required=False)

    def clean(self):
        cleaned_data = super(CreateUserForm, self).clean()

        # check if user with given email exists
        user_email = cleaned_data.get('user_email')
        if User.objects.filter(email=user_email):
            logger.warning('User %s already exists', user_email)
            raise ValidationError(_('User with given email already exists'))

        # check if passwords match
        user_password = cleaned_data.get('user_password')
        user_password_confirm = cleaned_data.get('user_password_confirm')
        if user_password and user_password_confirm and user_password != user_password_confirm:
            raise ValidationError(_('Passwords don\'t match'))

        # check if pins match
        user_pin = cleaned_data.get('user_pin')
        user_pin_confirm = cleaned_data.get('user_pin_confirm')
        if user_pin and user_pin_confirm and user_pin != user_pin_confirm:
            raise ValidationError(_('Pins don\'t match'))


# Vendor transaction form
class VendorTransactionForm(forms.Form):
    # product categories
    product_cats = [
        item.id for item in Product.objects.all()
    ]
    product_categories = forms.MultipleChoiceField(
        choices=[
            (item_id, item_id) for item_id in product_cats
        ]
    )

    # product amounts
    product_amounts = NotValidatedMultipleChoiceField()

    def clean_product_categories(self):
        product_categories = self.cleaned_data['product_categories']
        try:
            return map(int, product_categories)
        except ValueError:
            raise ValidationError(_('Category id\'s must be integers'))

    def clean_product_amounts(self):
        product_amounts = self.cleaned_data['product_amounts']
        try:
            return map(float, product_amounts)
        except ValueError:
            raise ValidationError(_('Amounts must be decimals'))


# Vendor transaction form
class VendorPaymentForm(forms.Form):
    # product categories
    uuids = [
        credit.uuid for credit in Credit.objects.all()
    ]
    credit_uuids = forms.MultipleChoiceField(
        choices=[
            (uuid, uuid) for uuid in uuids
        ]
    )

    # product amounts
    credit_amounts = NotValidatedMultipleChoiceField()

    def clean_credit_amounts(self):
        credit_amounts = self.cleaned_data['credit_amounts']
        try:
            return map(Decimal, credit_amounts)
        except ValueError:
            raise ValidationError(_('Amounts must be decimals'))


# Redeem vendors form
class RedeemVendorsForm(forms.Form):
    entity_marketplace_id = forms.IntegerField()
    vendors = NotValidatedMultipleChoiceField()

    def clean_entity_marketplace_id(self):
        id = self.cleaned_data['entity_marketplace_id']
        if not Marketplace.objects.filter(id=id):
            logger.warning('Invalid marketplace entity: %s', id)
            raise ValidationError(_('Invalid marketplace entity'))
        return id

    # TODO: think about whether its reasonable to do this check
    # can one marketplace issue a for vendors belonging to another?
    def clean_vendors(self):
        vendors = map(
            lambda x: int(x),
            self.cleaned_data['vendors']
        )
        logger.info('vendors: %s', vendors)
        if not vendors:
            raise ValidationError(_('To redeem credits, pick at least one vendor'))

        entity_marketplace_id = self.cleaned_data['entity_marketplace_id']
        marketplace = Marketplace.objects.get(id=entity_marketplace_id)
        marketplace_vendors = [
            vendor.id for vendor in marketplace.vendors.all()
        ]
        logger.info('marketplace vendors: %s', marketplace_vendors)

        # check that all vendors submitted belong the active marketplace
        for vendor_id in vendors:
            if not vendor_id in marketplace_vendors:
                raise ValidationError(_('Vendor not a member of marketplace %s') % marketplace.name)

        return vendors


# Create new user form
class CreateVendorForm(forms.Form):
    vendor_name = forms.CharField()
    vendor_email = forms.EmailField()
    vendor_invite_code = forms.CharField(required=False)

    # vendor product categories
    product_categories = [
        item.id for item in Product.objects.all()
    ]
    vendor_product_categories = forms.MultipleChoiceField(
        choices=[
            (item_id, item_id) for item_id in product_categories
        ]
    )

    # vendor venues
    venues = [
        item.id for item in Venue.objects.all()
    ]
    vendor_venues = forms.MultipleChoiceField(
        choices=[
            (item_id, item_id) for item_id in venues
        ]
    )

    # vendor csa
    vendor_has_csa = forms.BooleanField()

    def clean(self):
        cleaned_data = super(CreateVendorForm, self).clean()

        # check if user with given email exists
        vendor_name = cleaned_data.get('vendor_name')
        if Entity.objects.filter(name=vendor_name):
            logger.warning('Entity %s already exists', vendor_name)
            raise ValidationError(_('Entity with given name already exists'))


# Login existing user form
class LoginUserForm(forms.Form):
    user_name = forms.CharField(required=False)
    user_password = forms.CharField(required=False)
    user_qr_string = forms.CharField(required=False)
    user_pin = forms.IntegerField(min_value=1000, max_value=9999, required=False)

    def clean(self):
        cleaned_data = super(LoginUserForm, self).clean()
        login_password = cleaned_data['user_name'] and cleaned_data['user_password']
        login_qr = cleaned_data['user_qr_string'] and cleaned_data['user_pin']
        if not (login_password or login_qr):
            raise ValidationError(_('Either login or qr must be provided'))

        if login_qr:
            cleaned_data['login_qr'] = True
        else:
            cleaned_data['login_qr'] = False

        return cleaned_data


# Market venue and date
class DataExportForm(forms.Form):
    market_venue = forms.CharField()
    market_start_date = forms.CharField()
    market_end_date = forms.CharField()
    credit_type = forms.CharField()
    vendor = forms.CharField()

    def clean_market_start_date(self):
        data = self.cleaned_data['market_start_date']
        try:
            data = datetime.strptime(data, '%m/%d/%Y')
        except:
            logger.warn('Failed formatting date, picking default')
            data = datetime(2016,1,1)

        return data

    def clean_market_end_date(self):
        data = self.cleaned_data['market_end_date']
        try:
            data = datetime.strptime(data, '%m/%d/%Y')
        except:
            logger.warn('Failed formatting date, picking default')
            data = datetime(2020,1,1)

        return data


# Assign credit to user form
class AssignCreditToUserForm(forms.Form):
    credit_uuid = forms.UUIDField()
    credit_amount = forms.DecimalField(max_digits=12, decimal_places=2)


# Assign Users to Vendor
class EntityInviteOrAssignUsersForm(forms.Form):
    user_emails = NotValidatedMultipleChoiceField()

    def clean(self):
        cleaned_data = super(EntityInviteOrAssignUsersForm, self).clean()

        # check if user with given email exists
        user_emails = cleaned_data.get('user_emails')
        for user_email in user_emails:
            if '@' not in user_email:
                error_msg = 'Invalid email address submitted: %s' % user_email
                logger.warning(error_msg)
                raise ValidationError(_('error_msg'))

        return cleaned_data
