from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _

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


# Login existing user form
class LoginUserForm(forms.Form):
    cust_name = forms.CharField()
    cust_password = forms.CharField()
    cust_qr_string = forms.CharField()
    cust_pin = forms.IntegerField(min_value=1000, max_value=9999)


# Market venue and date
class MarketVenueDateForm(forms.Form):
    market_venue = forms.CharField()
    market_date = forms.CharField()

    def clean_market_date(self):
        data = self.cleaned_data['market_date']
        try:
            data = datetime.strptime(data, '%B %d, %Y')
            return data
        except:
            logger.warn('Tried formatting date, but failed once')

        try:
            data = datetime.strptime(data, '%b. %d, %Y')
            return data
        except:
            logger.warn('Tried formatting date, but failed once')

        return data

# Assign credit to user form
class AssignCreditToUserForm(forms.Form):
    credit_uuid = forms.UUIDField()
    credit_amount = forms.DecimalField(max_digits=12, decimal_places=2)
