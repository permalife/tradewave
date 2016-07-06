from django.db import transaction
from tradewave.models import Credit, Account, TransactionLog, Venue

import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TradewaveTransaction(object):
    def __init__(self, sender_account_id, recipient_account_id, venue_id):
        self.sender_account = Account.objects.get(id=sender_account_id)
        self.recipient_account = Account.objects.get(id=recipient_account_id)
        self.sender_name = self.sender_account.entity.name
        self.recipient_name = self.recipient_account.entity.name
        self.venue_id = venue_id
        self.amount_last_transacted = None

    def transact(self, credit_uuid, credit_amount, isRedeemed=False):
        credit = Credit.objects.get(uuid=credit_uuid)
        logger.info(
            'New transaction from %s to %s in credit %s (%s) requested',
            self.sender_name,
            self.recipient_name,
            credit.name,
            credit.uuid
        )

        # proceed as an atomic db transaction
        with transaction.atomic():
            # update, delete the asset for this credit in the sender's wallet or
            # throw an exception in of insufficient funds
            try:
                sender_creditmap = self.sender_account.creditmap_set.get(credit_id=credit_uuid)
            except Exception as e:
                logger.error(
                    'Sender %s does not have credit %s (%s) in their account',
                    self.sender_name,
                    credit.name,
                    credit.uuid
                )
                raise e

            if sender_creditmap.amount > credit_amount:
                sender_creditmap.amount -= credit_amount
                sender_creditmap.save()
                db_transaction = 'update'
            elif sender_creditmap.amount == credit_amount:
                sender_creditmap.delete()
                db_transaction = 'delete'
            else:
                raise Exception('Insufficient funds')

            logger.info(
                'Account asset for credit %s (%s) will be %sd for sender %s',
                credit.name,
                str(credit.uuid),
                db_transaction,
                self.sender_name
            )

            # create or update the asset in recipients wallet
            recipient_creditmap, wasCreated = self.recipient_account.creditmap_set.get_or_create(
                credit_id=credit_uuid,
                defaults = {'amount': credit_amount}
            )

            if wasCreated:
                db_transaction = 'create'
            else:
                recipient_creditmap.amount += credit_amount
                recipient_creditmap.save()
                db_transaction = 'update'

            logger.info(
                'Account asset for credit %s (%s) will be %sd for recipient %s',
                credit.name,
                str(credit.uuid),
                db_transaction,
                self.recipient_name
            )

            # update transaction log
            tr_log = TransactionLog(
                transact_from=self.sender_account,
                transact_to=self.recipient_account,
                credit=credit,
                amount=credit_amount,
                venue=Venue.objects.get(id=self.venue_id),
                redeemed=isRedeemed
            )
            tr_log.save()
            logger.info(' '.join(
                [
                    'Log transaction of credit',
                    '%s (%s) from %s to %s in the amount of %.2f',
                ]),
                credit.name,
                str(credit.uuid),
                self.sender_name,
                self.recipient_name,
                credit_amount
            )

            # adjust account total records
            self.sender_account.amount_total -= credit_amount
            self.recipient_account.amount_total += credit_amount

            # save the changes to account totals
            self.sender_account.save()
            self.recipient_account.save()
            self.amount_last_transacted = credit_amount
            logger.info('Transaction %s completed', tr_log.uuid)
