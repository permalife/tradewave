from django.db import models
from django.contrib.auth.models import User


# defines city (municipality)
class City(models.Model):
    name = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    country = models.CharField(max_length=30)

    class Meta:
        unique_together = ('name', 'state', 'country')

    def __unicode__(self):
        return ' '.join(['City:', self.name])


# defines venue
class Venue(models.Model):
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    zipcode = models.CharField(max_length=5)
    city = models.ForeignKey(City)
    date_created = models.DateTimeField()
    date_active = models.DateTimeField()

    def __unicode__(self):
        return ' '.join([
            'Venue:',
            self.name,
            'at',
            self.city.name,
        ])


# defines entity
# notes:
#   Entities are objects that can be either personal, vendors or marketplaces
#   A personal entity is tied to user's personal account. It can not issue credits.
#   A vendor or marketplace entity have their own accounts that multiple users can manage.
#   A vendor or marketplace accounts are capable of issuing credits.
class Entity(models.Model):
    name = models.CharField(max_length=100, unique=True)
    date_created = models.DateTimeField()
    date_active = models.DateTimeField()

    # entity reputation
    rating = models.FloatField()

    # venues the marketplace is registered for
    venues = models.ManyToManyField(Venue, through='VenueMap')

    class Meta:
        permissions = (
            ("entity_admin", "Can administer entity"),
            ("entity_manager", "Can manage entity"),
            ("entity_employee", "Is entity employee"),
        )

    def __unicode__(self):
        return self.name


# maps entities to venues
class VenueMap(models.Model):
    entity = models.ForeignKey(Entity)
    venue = models.ForeignKey(Venue)

    def __unicode__(self):
        return ' '.join([
            self.entity.name,
            "at",
            self.venue.name
        ])


# defines the types of credits issued
class Credit(models.Model):
    # unique user identifier
    credit_id = models.UUIDField(primary_key=True)

    # credit name as per issuer's choosing
    name = models.CharField(max_length=100)

    # credits are tied to entities
    issuer = models.ForeignKey('Account')

    # current credit generation (i.e. 6th time issued)
    series = models.IntegerField()

    # total amount issued in USD
    amount_issued = models.FloatField()

    # total amount redeemed to date in USD
    amount_redeemed = models.FloatField()

    # redeemed / issued (meaningful for comleted credit series)
    credit_rating = models.FloatField()

    date_issued = models.DateTimeField('date issued')
    date_expire = models.DateTimeField('date to expire')
    date_lastspent = models.DateTimeField('date last transaction')

    def __unicode__(self):
        return ' '.join([
            "credit",
            self.name,
            "series #",
            self.series,
            "issued by",
            self.issuer.name,
        ])


# defines account(s) associated with an entity
class Account(models.Model):
    # total amount in USD of credits held
    total_amount = models.FloatField()

    # maximum amount of credits to issue
    max_credit_issued = models.FloatField()

    # maximum amount of credits that can be held in account
    max_credit_held = models.FloatField()

    # account holder's wallet
    wallet = models.ManyToManyField(Credit, through='CreditMap')

    # entity that owns the account
    entity = models.ForeignKey(Entity)

    class Meta:
        permissions = (
            ("credits_issue", "Can issue credits"),
            ("credits_transact", "Can transact in credits"),
        )

    def __unicode__(self):
        return self.entity.name + '\'s account'


# maps credits to accounts
class CreditMap(models.Model):
    holder = models.ForeignKey(Account)
    credit = models.ForeignKey(Credit)
    amount = models.FloatField()

    def __unicode__(self):
        return ' '.join([
            str(self.amount),
            "of",
            self.credit.name,
            "credits held by",
            self.holder.name,
        ])


# define industry type
# (e.g. Food, Construction, Law, Medical, Etc.)
class Industry(models.Model):
    name = models.CharField(max_length=64, unique=True)


# define vendor
class Vendor(Entity):
    industry = models.ForeignKey(Industry)

    # does vendor has a CSA
    is_csa = models.BooleanField()


# define marketplace
class Marketplace(Entity):
    # marketplaces are assigned to cities, but vendors are not
    city = models.ForeignKey(City)

    # vendors that operate within the marketplace
    vendors = models.ManyToManyField(Vendor, through='Affiliation')

    def __unicode__(self):
        return ' '.join([
            "marketplace:",
            self.name,
            "in",
            self.city.name
        ])


# maps to registered users and define various user properties
# notes:
#   We use Django's built-in user object for authentication.
#   A user has a personal account and can be affiliated with vendors and/or marketplaces
class UserProperty(models.Model):
    # unique user identifier
    userid = models.UUIDField(primary_key=True)

    # reference to django's user object
    user = models.OneToOneField(User, unique=True)
    date_created = models.DateTimeField('date joined')
    date_active = models.DateTimeField('date last active')

    # personal id number
    pin = models.IntegerField()

    # vendor affiliation
    vendors = models.ManyToManyField(Vendor, related_name='vendor', blank=True)

    # marketplace affiliation
    marketplaces = models.ManyToManyField(Marketplace, related_name='marketplace', blank=True)

    # link to a personal account
    # for regular users (with no affiliations), this will be their only account
    # if a user is affiliated with a vendor and/or marketplace, they will have access
    # to additional accounts through these affiliations
    account_holder = models.ForeignKey(Account, related_name='account_holder')

    # represents a passive relationship with an entity
    # ('like', 'follow', etc)
    favorites = models.ManyToManyField(Entity, through='Relationship')

    def __unicode__(self):
        return ' '.join([
            "user properties of",
            self.user.username,
        ])


# define relationships
# (e.g. "like", "follow", etc)
class Relationship(models.Model):
    user = models.ForeignKey(UserProperty)
    entity = models.ForeignKey(Entity)
    type_r = models.CharField(unique=True, max_length=50)

    # date relationship commenced
    date_started = models.DateField()


# maps affiliations between a vendor and marketplace
class Affiliation(models.Model):
    marketplace = models.ForeignKey(Marketplace)
    vendor = models.ForeignKey(Vendor)

    # date affiliation began
    date_started = models.DateField()


# defines transaction log (record of all transactions)
class TransactionLog(models.Model):
    timestamp = models.DateTimeField("transaction timestamp")
    transact_from = models.ForeignKey(
        CreditMap,
        related_name="sender"
    )
    transact_to = models.ForeignKey(
        CreditMap,
        related_name="receiver"
    )
    amount = models.FloatField()
    venue = models.ForeignKey(Venue)

    # boolean flag to indicate whether the credit was
    # extinguished as a result of the transaction
    redeemed = models.BooleanField()

    def __unicode__(self):
        return ' '.join([
            'Transaction:',
            str(self.amount),
            self.transact_from.credit.name + "'s",
            "credits from",
            self.transact_from.holder.name,
            "sent to",
            self.transact_to.holder.name
        ])
