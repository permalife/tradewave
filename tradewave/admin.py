from django.contrib import admin

# Register your models here.
from tradewave.models import City, Venue, Entity, VenueMap, Credit, \
    Account, CreditMap, TradewaveUser, Relationship, Industry, Vendor, \
    Marketplace, Affiliation, TransactionLog

from import_export import resources
#from import_export.admin import ImportExportActionModelAdmin
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
admin.site.register(Entity)
admin.site.register(Venue)
admin.site.register(VenueMap)
admin.site.register(Credit)
admin.site.register(Account)
admin.site.register(CreditMap)
admin.site.register(TradewaveUser)
admin.site.register(Relationship)
admin.site.register(Industry)
admin.site.register(Vendor)
admin.site.register(Marketplace)
admin.site.register(Affiliation)
admin.site.register(TransactionLog)
