from django.db import models
from django.contrib.auth.models import User

# producer credit table
class Credit(models.Model):
    name = models.CharField(max_length=100) # credit name as per Vendor's choosing
    issuer = models.ForeignKey(User) # issuer id
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
# this uses a reference to django's built in user model
class UserProperty(models.Model):
    user = models.OneToOneField(User, primary_key=True)     
    date_created = models.DateTimeField('date joined') 
    date_active = models.DateTimeField('date last active') 
    is_vendor = models.BooleanField() # boolean flag to indicate is the user is a vendor
    pin = models.IntegerField() # personal id number
    total_amount = models.FloatField() # total amount in USD of credits held
 
    def __unicode__(self):
        return ' '.join([self.user.username + "'s",
                         "user properties"])

# vendor properties table
# this uses a reference to django's built in user model
class VendorProperty(models.Model):
    user = models.OneToOneField(User, primary_key=True) 
    name = models.CharField(max_length=100) # vendor's name
    vendor_rating = models.FloatField() # average over credit ratings issued by vendor
    credit_ceiling = models.FloatField() # maximum total amount across unredeemed credits

    def __unicode__(self):
        return ' '.join([self.user.username + "'s",
                         "vendor properties"])

# vendor admin table (maps admins to vendors)
class VendorAdmin(models.Model):
    user = models.ForeignKey(User, related_name="vendor_admin")
    admin_for = models.ForeignKey(User, related_name="vendor_administered")

    def __unicode__(self):
        return ' '.join([self.user.username,
                         "(%s's admin)" % self.admin_for.username])

# vendor manager table (maps managers to vendors)
class VendorManager(models.Model):
    user = models.ForeignKey(User, related_name="vendor_manager")
    manager_for = models.ForeignKey(User, related_name="vendor_managed")
    
    def __unicode__(self):
        return ' '.join([self.user.username,
                         "(%s's manager)" % self.manager_for.username])

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

# marketplace table
class Marketplace(models.Model):
    name = models.CharField(max_length=100)
    city = models.ForeignKey(City)
    date_created = models.DateTimeField()
    date_active = models.DateTimeField()
    num_members = models.IntegerField("number of members") # total number of vendors in the marketplace

    def __unicode__(self):
        return ' '.join(["Marketplace:", self.name]) 

# marketplace table
# marketplace admin table (maps admins to marketplaces)
class MarketplaceAdmin(models.Model):
    user = models.ForeignKey(User)
    admin_for = models.ForeignKey(Marketplace)

    def __unicode__(self):
        return ' '.join([self.user.username,
                         "(%s's admin)" % self.admin_for.name])

# marketplace manager table (maps managers to marketplaces)
class MarketplaceManager(models.Model):
    user = models.ForeignKey(User)
    manager_for = models.ForeignKey(Marketplace)

    def __unicode__(self):
        return ' '.join([self.user.username,
                         "(%s's manager)" % self.manager_for.name])

# marketplace venue table (maps venues to marketplaces)
class MarketplaceVenue(models.Model):
    venue = models.ForeignKey(Venue)
    marketplace = models.ForeignKey(Marketplace)

    def __unicode__(self):
        return ' '.join([self.venue.name, 
                         "member of", 
                         self.marketplace.name]) 

# marketplace vendor table (maps vendors to marketplaces)
class MarketplaceVendor(models.Model):
    vendor = models.ForeignKey(User)
    marketplace = models.ForeignKey(Marketplace)

    def __unicode__(self):
        return ' '.join([self.vendor.username, 
                         "member of", 
                         self.marketplace.name]) 
