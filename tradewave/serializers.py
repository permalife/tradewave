from rest_framework import serializers
from tradewave.models import Account, TransactionLog

class AccountSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Account
        fields = ('id', 'amount_total', 'date_created', 'date_last_transacted')

class TransactionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransactionLog
        fields = ('uuid', 'transact_from', 'transact_to', 'amount', 'date_transacted')
        pandas_index = ['uuid']
