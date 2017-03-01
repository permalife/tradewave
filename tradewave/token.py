from tradewave.models import Token

from datetime import datetime
import pytz


class TokenRecord(object):
    def __init__(self, token):
        self.token_record = None
        if Token.objects.filter(token=token):
            self.token_record = Token.objects.get(token=token)

    def is_valid(self):
        token = self.token_record
        is_token_not_verified = token and not token.is_verified
        is_token_not_expired = token and datetime.now(pytz.utc) < token.date_expires
        return is_token_not_verified and is_token_not_expired

    def get_email(self):
        if self.token_record:
            return token_record.email
        else:
            return None

    def get_vendor(self):
        return token_record.vendor

    def get_marketplace(self):
        return token_record.marketplace
