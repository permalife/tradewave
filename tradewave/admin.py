from django.contrib import admin

# Register your models here.
from tradewave.models import City, Venue, Entity, VenueMap, Credit, \
    AccountHolder, CreditMap, UserProperty, Relationship, Industry, Vendor, \
    Marketplace, Affiliation, TransactionLog

admin.site.register(City)
admin.site.register(Venue)
admin.site.register(VenueMap)
admin.site.register(Credit)
admin.site.register(AccountHolder)
admin.site.register(CreditMap)
admin.site.register(UserProperty)
admin.site.register(Relationship)
admin.site.register(Industry)
admin.site.register(Vendor)
admin.site.register(Marketplace)
admin.site.register(Affiliation)
admin.site.register(TransactionLog)
