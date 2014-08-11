from django.contrib import admin

# Register your models here.
from tradewave.models import Credit, UserProperty, VendorProperty, VendorAdmin, VendorManager, Wallet, City, Venue, TransactionLog, VendorVenue, Marketplace, MarketplaceAdmin, MarketplaceManager, MarketplaceVenue, MarketplaceVendor

admin.site.register(Credit)
admin.site.register(UserProperty)
admin.site.register(VendorProperty)
admin.site.register(VendorAdmin)
admin.site.register(VendorManager)
admin.site.register(Wallet)
admin.site.register(City)
admin.site.register(Venue)
admin.site.register(TransactionLog)
admin.site.register(VendorVenue)
admin.site.register(Marketplace)
admin.site.register(MarketplaceAdmin)
admin.site.register(MarketplaceManager)
admin.site.register(MarketplaceVenue)
admin.site.register(MarketplaceVendor)
