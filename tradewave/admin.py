from django.contrib import admin

# Register your models here.
from tradewave.models import \
    City, Venue, \
    TradewaveUser, \
    Entity, EntityVenues, \
    Vendor, \
    Marketplace, MarketplaceVendors, \
    Credit, Account, CreditMap, TransactionLog, \
    Product, CreditProductMap, \
    Relationship
    #VendorProducts, \

from import_export import resources
from import_export.admin import ImportExportModelAdmin


class CreditMapResource(resources.ModelResource):

    class Meta:
        model = CreditMap
        fields = (
            'account__entity__name',
            'credit__name',
            'amount',
            'account__date_last_transacted'
        )
        exclude = ('id',)


class CreditMapAdmin(ImportExportModelAdmin):
    resource_class = CreditMapResource
    pass


admin.site.register(City)
admin.site.register(Venue)
admin.site.register(TradewaveUser)
admin.site.register(Entity)
admin.site.register(EntityVenues)
admin.site.register(Vendor)
admin.site.register(Marketplace)
admin.site.register(MarketplaceVendors)
admin.site.register(Credit)
admin.site.register(Account)
admin.site.register(CreditMap)
admin.site.register(TransactionLog)
admin.site.register(Product)
admin.site.register(CreditProductMap)
admin.site.register(Relationship)
