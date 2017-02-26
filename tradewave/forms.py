from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _

from tradewave.models import Product, Venue, Entity, TradewaveUser

from datetime import datetime

import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


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


# Create new user form
class CreateVendorForm(forms.Form):
    vendor_name = forms.CharField()
    vendor_email = forms.EmailField()
    vendor_invite_code = forms.CharField(required=False)

    # vendor product categories
    try:
        product_categories = [
            item.id for item in Product.objects.all()
        ]
    except:
        product_categories = []

    vendor_product_categories = forms.MultipleChoiceField(
        choices=[
            (item_id, item_id) for item_id in product_categories
        ]
    )

    # vendor venues
    try:
        venues = [
            item.id for item in Venue.objects.all()
        ]
    except:
        venues = []

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
    cust_name = forms.CharField()
    cust_password = forms.CharField()
    cust_qr_string = forms.CharField()
    cust_pin = forms.IntegerField(min_value=1000, max_value=9999)


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


class NotValidatedMultipleChoiceFiled(forms.TypedMultipleChoiceField):
    """Field that do not validate if the field values are in self.choices"""

    def to_python(self, value):
        """Override checking method"""
        return map(self.coerce, value)

    def validate(self, value):
        """Nothing to do here"""
        pass


# Assign Users to Vendor
class AssignUsersToVendorForm(forms.Form):
    user_emails = NotValidatedMultipleChoiceFiled()

    def clean(self):
        cleaned_data = super(AssignUsersToVendorForm, self).clean()

        # check if user with given email exists
        user_emails = cleaned_data.get('user_emails')
        for user_email in user_emails:
            if '@' not in user_email:
                error_msg = 'Invalid email address submitted: %s' % user_email
                logger.warning(error_msg)
                raise ValidationError(_('error_msg'))

        return cleaned_data
