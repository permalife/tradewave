from tradewave.models import Account, Credit, CreditMap, Vendor
from scipy.optimize import minimize
from operator import attrgetter

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class CreditAllocations(object):
    def __init__(self, transaction_data, cust_account_personal_id, vendor_id):
        # transaction_data is a dict mapping product_id's to product amounts
        self.A = transaction_data.values()
        self.n = len(self.A)
        assert(self.n > 0)

        # determine which marketplaces the vendor belongs to
        vendor = Vendor.objects.get(id=vendor_id)
        marketplace_ids = [item.id for item in vendor.marketplace_set.all()]

        # generate the list of customer's credits for the marketplace
        cust_account = Account.objects.get(id=cust_account_personal_id)
        cust_wallet = CreditMap.objects.filter(account=cust_account)
        self.cust_credits = dict([
            (entry.credit.uuid, float(entry.amount))
            for entry in sorted(cust_wallet, key=attrgetter('amount'), reverse=True)
            if entry.credit.issuer.id in marketplace_ids
        ])
        logger.info('Customer credits: %s', self.cust_credits)

        self.C = self.cust_credits.values()
        self.m = len(self.C)

        i = 0
        self.D = []
        for credit_id in self.cust_credits.keys():
            rowD = [
                self._can_buy(credit_id, product_id)
                for product_id in transaction_data.keys()
            ]
            self.D.append(rowD)
            i += 1
        logger.info('product <=> credit matrix: %s', self.D)

        self._define_constraints()
        self._define_bounds_x0()

    def _define_constraints(self):
        self.cons = []

        # try to pay requested amount for each item
        for i in xrange(self.n):
            self.cons.append({
                'type': 'ineq',
                'fun': lambda x, i=i: self.A[i] - sum(x[i * self.m : (i+1) * self.m])
            })

        # can not exceed the amount of credit held for each credit type
        for j in xrange(self.m):
            self.cons.append({
                'type': 'ineq',
                'fun': lambda x, j=j: self.C[j] - sum(x[j : self.n * self.m : self.m])
            })

    def _define_bounds_x0(self):
        # define bounds and the initial guess
        self.bnds = []
        self.x0 = []
        for i in xrange(self.n):
            for j in xrange(self.m):
                upper = 0
                if self.D[j][i]:
                    upper = self.C[j]
                self.bnds.append((0, upper))
                self.x0.append(0)

    def compute(self):
        # main cost function
        def f(x):
            f = 0
            for i in xrange(self.n):
                s = sum(x[i * self.m : (i+1) * self.m])
                f += (self.A[i] - s)
            return f

        # run the algorithm
        res = minimize(
            f,
            self.x0,
            method='SLSQP',
            bounds=self.bnds,
            constraints=self.cons
        )

        i = 0
        credit_data = {}
        for credit_id in self.cust_credits.keys():
            credit_amount = sum(res['x'][i : self.n * self.m : self.m])
            if credit_amount >= 1e-2:
                logger.info('Paying %s in credit %d', credit_amount, credit_id)
                credit_data[credit_id] = credit_amount
            i += 1

        return credit_data

    # returns 1 if credit can buy item with id=product_id, else returns 0
    def _can_buy(self, credit_id, product_id):
        credit = Credit.objects.get(uuid=credit_id)
        if (not credit.is_restricted) or credit.products.filter(id=product_id):
            return 1
        else:
            return 0
