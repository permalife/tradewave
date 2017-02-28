from collections import OrderedDict
from operator import attrgetter

from tradewave.models import CreditMap, Entity


class Wallet(object):
    def __init__(self, entity_id):
        self.entity = Entity.objects.get(id=entity_id)
        self.account = self.entity.account_set.first()

    def get_account_id(self):
        return self.account.id

    def get_wallet(self):
        self.wallet = CreditMap.objects.filter(account=self.account)
        return self.wallet

    def get_credit_amounts_by_name(self):
        credits = OrderedDict([
            (entry.credit.name, float(entry.amount))
            for entry in sorted(self.get_wallet(), key=attrgetter('amount'), reverse=True)
        ])
        return credits

    def get_credit_names_by_uuid(self):
        credits = dict([
            (
                str(entry.credit.uuid),
                {'name': entry.credit.name, 'amount': entry.amount}
            )
            for entry in self.get_wallet()
        ])
        return credits

    def get_total(self):
        return self.account.amount_total
