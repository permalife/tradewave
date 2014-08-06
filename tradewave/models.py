from django.db import models
from django.contrib.auth.models import User

# producer credit table
class Credit(models.Model):
    name = models.CharField(max_length=100) # credit name as per Vendor's choosing
    issuerid = models.ForeignKey(User) # issuer id
    amount_issued = models.FloatField() # total amount issued in USD
    amount_redeemed = models.FloatField() # total amount redeemed to date in USD
    series = models.IntegerField() # current credit generation (i.e. 6th time issued)
    credit_rating = models.FloatField() # redeemed / issued over all generations
    date_created = models.DateTimeField('date created') # date credit was created
    date_expire = models.DateTimeField('date to expire') # date credit set to expire
    date_lastspent = models.DateTimeField('date last transaction') 

# user properties table
# *** we intend to use Django's user object
# this uses a reference to django's built in user model
class UserProperties(models.Model):
    userid = models.OneToOneField(User, primary_key=True)     
    date_created = models.DateTimeField('date joined') 
    date_active = models.DateTimeField('date last active') 
    is_vendor = models.BooleanField() # boolean flag to indicate is the user is a vendor
    pin = models.IntegerField() # personal id number
    total_amount = models.FloatField() # total amount in USD of credits held

# vendor properties table
# this uses a reference to django's built in user model
class VendorProperties(models.Model):
    userid = models.OneToOneField(User, primary_key=True) 
    name = models.CharField(max_length=100) # vendor's name
    vendor_rating = models.FloatField() # average over credit ratings issued by vendor
    credit_ceiling = models.FloatField() # maximum total amount across unredeemed credits

# vendor admin table (maps admins to vendors)
class VendorAdmin(models.Model):
    userid = models.ForeignKey(User, related_name="vendor_admin")
    admin_for = models.ForeignKey(User, related_name="vendor_administered")

# vendor manager table (maps managers to vendors)
class VendorManager(models.Model):
    userid = models.ForeignKey(User, related_name="vendor_manager")
    manager_for = models.ForeignKey(User, related_name="vendor_managed")
    
# wallet table (maps credits to credit holders and specifies amounts)
class Wallet(models.Model):
    userid = models.ForeignKey(User)
    creditid = models.ForeignKey(Credit)
    amount = models.FloatField()

# city (municipality) table
class City(models.Model):
    name = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    country = models.CharField(max_length=30)     

# venue table
class Venue(models.Model):
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    zipcode = models.CharField(max_length=10)
    cityid = models.ForeignKey(City)
    date_created = models.DateTimeField()
    date_active = models.DateTimeField()

# transaction log table (record of transactions using wallet references)  
class TransactionLog(models.Model):
    timestamp = models.DateTimeField("transaction timestamp")
    wallet_send = models.ForeignKey(Wallet, related_name="sender")
    wallet_receive = models.ForeignKey(Wallet, related_name="receiver")
    creditid = models.ForeignKey(Credit)
    amount = models.FloatField()
    venueid = models.ForeignKey(Venue)
    redeemed = models.BooleanField() # boolean flag to indicate whether the credit was
                                     # extinguished as a result of the transaction
# vendor venue table (can map vendors to venues, even
# if they are not part of a marketplace)
class VendorVenue(models.Model):
    vendorid = models.ForeignKey(User)
    venueid = models.ForeignKey(Venue)

# marketplace table
class Marketplace(models.Model):
    name = models.CharField(max_length=100)
    cityid = models.ForeignKey(City)
    date_created = models.DateTimeField()
    date_active = models.DateTimeField()
    num_vendors = models.IntegerField() # total number of vendors in the marketplace

# marketplace admin table (maps admins to marketplaces)
class MarketplaceAdmin(models.Model):
    userid = models.ForeignKey(User)
    admin_for = models.ForeignKey(Marketplace)

# marketplace manager table (maps managers to marketplaces)
class MarketplaceManager(models.Model):
    userid = models.ForeignKey(User)
    manager_for = models.ForeignKey(Marketplace)

# marketplace venue table (maps venues to marketplaces)
class MarketplaceVenue(models.Model):
    venueid = models.ForeignKey(Venue)
    marketplaceid = models.ForeignKey(Marketplace)

# marketplace vendor table (maps vendors to marketplaces)
class MarketplaceVendor(models.Model):
    vendorid = models.ForeignKey(User)
    marketplaceid = models.ForeignKey(Marketplace)
