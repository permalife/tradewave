from tradewave.models import TradewaveUser
from tradewave.wallet import Wallet

class TwUser(object):
    def __init__(self, userid):
        self.tw_user = TradewaveUser.objects.get(user_id=userid)
        self.entity_user = self.tw_user.user_entity

        if self.is_marketplace():
            self.entity = self.tw_user.marketplaces.first()

        if self.is_vendor():
            self.entity = self.tw_user.vendors.first()

        self.wallet_user = Wallet(self.entity_user.id)
        self.wallet_entity = None
        if self.entity:
            self.wallet_entity = Wallet(self.entity.id)

    def get_username(self):
        return tw_user.user.username

    def get_entity_personal(self):
        return self.entity_user

    def is_marketplace(self):
        return self.tw_user and self.tw_user.marketplaces.exists()

    def is_vendor(self):
        return self.tw_user and self.tw_user.vendors.exists()

    def get_entity_id(self):
        if self.entity:
            return self.entity.id
        else:
            return None

    def get_entity_name(self):
        if self.entity:
            return self.entity.name
        else:
            return None

    def get_entity(self):
        return self.entity

    def get_personal_account_id(self):
        return self.wallet_user.get_account_id()

    def get_entity_account_id(self):
        if self.entity:
            return self.wallet_entity.get_account_id()
        else:
            return None

    def get_personal_wallet(self):
        return self.wallet_user

    def get_entity_wallet(self):
        return self.wallet_entity
