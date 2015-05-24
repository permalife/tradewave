from django.db import models
from django.contrib.auth.models import User

# producer credit table
class Credit(models.Model):
    name = models.CharField(max_length=100) # credit name as per Vendor's choosing
    issuer = models.ForeignKey(Entity) # Credits are tied to new Entities class rather than users.
    amount_issued = models.FloatField() # total amount issued in USD
    amount_redeemed = models.FloatField() # total amount redeemed to date in USD
    series = models.IntegerField() # current credit generation (i.e. 6th time issued)
    credit_rating = models.FloatField() # redeemed / issued over all generations
    date_created = models.DateTimeField('date created') # date credit was created
    date_expire = models.DateTimeField('date to expire') # date credit set to expire
    date_lastspent = models.DateTimeField('date last transaction') 

    def __unicode__(self):
       return ' '.join(['Credit:', self.name])

# user properties table
# *** we intend to use Django's user object
# this uses a reference to django's built-in user model
class UserProperty(models.Model):
    user = models.OneToOneField(User, primary_key=True)     
    date_created = models.DateTimeField('date joined') 
    date_active = models.DateTimeField('date last active') 
    pin = models.IntegerField() # personal id number
    total_amount = models.FloatField() # total amount in USD of credits held
	favorites = ManyToManyField(Entity) # Represents a passive relationship with an entity. Like, Follow, etc.
 
    def __unicode__(self):
        return ' '.join([self.user.username + "'s",
                         "user properties"])

# Entities are objects that can create and distribute credits. 
# For now this is only markets and vendors, but this could change in the future
class Entity(models.Model):
    name = models.CharField(max_length=100)
    date_created = models.DateTimeField()
    date_active = models.DateTimeField()
	users = ManyToManyField(User, through='Permissions') # Represents a working relationship with a User. Admin, Manager, etc.	
	
    class Meta:
        abstract = True

# Data about working User-Entity relationships. Determines the level of access a User has to an Entity
class Permissions(models.Model):
    user = models.ForeignKey(User)
    entity = models.ForeignKey(Entity)
    date_granted = models.DateField()
    access_level = models.CharField(max_length=64) # Admin, Manager, Employee, etc. Should this be another class?
# class AccessLevel(models.Model)
	
# vendor table
# expands the Entity class
class Vendor(Entity):
	industry = models.ForeignKey(Industry) # Type of business. (Food, Construction, Law, Medical, Etc.)    


class Industry(models.Model):
	name = models.CharField(max_length=64)

# vendor properties table
class VendorProperty(models.Model):
    name = models.CharField(max_length=100) # vendor's name
    vendor_rating = models.FloatField() # average over credit ratings issued by vendor
    credit_ceiling = models.FloatField() # maximum total amount across unredeemed credits


# marketplace table
# expands the Entity class
class Marketplace(Entity):
    city = models.ForeignKey(City) # Marketplaces are location based, but Vendors are not.
    vendors = ManyToManyField(Vendor, through='Relationship') # Vendors that operate within the marketplace

    def __unicode__(self):
        return ' '.join(["Marketplace:", self.name])

# Describes the relationship between a Vendor and Marketplace
class Relationship(models.Model):
	marketplace = models.ForeignKey(Marketplace)
	vendor = models.ForeignKey(Vendor)
	date_joined: models.DateField()

# marketplace properties table
class MarketplaceProperty(models.Model):
    marketplace_rating = models.FloatField() # average over credit ratings issued by marketplace
    credit_ceiling = models.FloatField() # maximum total amount across unredeemed credits

# Manager/Admin relationships handled by Permissions

# wallet table (maps credits to credit holders and specifies amounts)
class Wallet(models.Model):
    user = models.ForeignKey(User)
    credit = models.ForeignKey(Credit)
    amount = models.FloatField()

    def __unicode__(self):
        return ' '.join([ str(self.amount),
                          "of",
                          self.user.username + "'s", 
                          self.credit.name,
                          "credits"]) 

# city (municipality) table
class City(models.Model):
    name = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    country = models.CharField(max_length=30)     

    def __unicode__(self):
        return ' '.join(['City:', self.name]) 

# venue table
class Venue(models.Model):
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    zipcode = models.CharField(max_length=10)
    city = models.ForeignKey(City)
    date_created = models.DateTimeField()
    date_active = models.DateTimeField()

    def __unicode__(self):
        return ' '.join(['Venue:', self.name]) 

# transaction log table (record of transactions using wallet references)  
class TransactionLog(models.Model):
    timestamp = models.DateTimeField("transaction timestamp")
    wallet_send = models.ForeignKey(Wallet, related_name="sender")
    wallet_receive = models.ForeignKey(Wallet, related_name="receiver")
    credit = models.ForeignKey(Credit)
    amount = models.FloatField()
    venue = models.ForeignKey(Venue)
    redeemed = models.BooleanField() # boolean flag to indicate whether the credit was
                                     # extinguished as a result of the transaction
    def __unicode__(self):
        return ' '.join(['Transaction:', 
                         str(self.amount),
                         self.credit.name + "'s",
                         "credits from",
                         self.wallet_send.user.username,
                         "sent to",
                         self.wallet_receive.user.username]) 

# vendor venue table (can map vendors to venues, even
# if they are not part of a marketplace)
class VendorVenue(models.Model):
    vendor = models.ForeignKey(User)
    venue = models.ForeignKey(Venue)

    def __unicode__(self):
        return ' '.join([self.vendor.username, "at", self.venue.name]) 

# Admin/Manager data handled by Permissions

# marketplace venue table (maps venues to marketplaces)
class MarketplaceVenue(models.Model):
    venue = models.ForeignKey(Venue)
    marketplace = models.ForeignKey(Marketplace)

    def __unicode__(self):
        return ' '.join([self.venue.name, 
                         "member of", 
                         self.marketplace.name])
