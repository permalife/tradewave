from django.conf.urls import url, include
#from django.contrib.auth.models import User
from rest_framework import routers, viewsets
from tradewave import views

# Routers provide an easy way of automatically determining the URL conf.
#router = routers.DefaultRouter()
#router.register(r'accounts', views.account_list)

urlpatterns = [
    # API
    #url(r'^', include(router.urls)),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^accounts/$', views.AccountList.as_view(), name='accounts'),
    url(r'^accounts/(?P<pk>[0-9]+)/$', views.AccountDetail.as_view()),
    url(r'^transaction-logs/$', views.TransactionLogList.as_view(), name='transaction-logs'),
    url(r'^transaction-logs/(?P<uuid>[\w-]+)/$', views.TransactionLogDetail.as_view()),
    url(r'^transaction-logs/entity/spent/(?P<account_id>\d+)/$', views.TransactionLogEntitySpentPandas.as_view(), name='transactions-spent'),
    url(r'^transaction-logs/entity/received/(?P<account_id>\d+)/$', views.TransactionLogEntityReceiviedPandas.as_view(), name='transactions-received'),

    # template views
    url(r'^$', views.LoginView.as_view(), name='root'),
    url(r'^login/(?P<status_msg>.*)/$', views.LoginView.as_view(), name='login'),
    url(r'^send/$', views.SendView.as_view(), name='send'),
    url(r'^confirm-send/$', views.ConfirmSendView.as_view(), name='confirm-send'),
    url(r'^confirm-receive/$', views.ConfirmReceiveView.as_view(), name='confirm-receive'),
    url(r'^create-user/$', views.CreateUser.as_view(), name='create-user'),
    url(r'^create-user/(?P<vendor_id>\d+)/(?P<vendor_name>\w+)/(?P<status_msg>.*)/$', views.CreateUser.as_view(), name='create-user-vendor'),
    url(r'^create-user-new/(?P<invite_token>\w{8}-\w{4}-\w{4}-\w{4}-\w{12})/$', views.CreateUserNew.as_view(), name='create-user-new'),
    url(r'^create-vendor/$', views.CreateVendor.as_view(), name='create-vendor'),
    url(r'^create-vendor/(?P<status_msg>.*)/$', views.CreateVendor.as_view(), name='create-vendor-status'),
    url(r'^dashboard/$', views.DashboardView.as_view(), name='dashboard'),
    url(r'^load-ddip/$', views.LoadDdipView.as_view(), name='load-ddip'),
    url(r'^marketplace-initial/$', views.MarketplaceInitial.as_view(), name='marketplace-initial'),
    url(r'^marketplace-issue/$', views.MarketplaceIssue.as_view(), name='marketplace-issue'),
    url(r'^marketplace-issue-login/$', views.MarketplaceIssueLogin.as_view(), name='marketplace-issue-login'),
    url(r'^marketplace-issue-pick-credit/$', views.MarketplaceIssuePickCredit.as_view(), name='marketplace-issue-pick-credit'),
    url(r'^marketplace-redeem/$', views.MarketplaceRedeem.as_view(), name='marketplace-redeem'),
    url(r'^marketplace-home/$', views.MarketplaceHome.as_view(), name='marketplace-home'),
    url(r'^marketplace-home/(?P<status_msg>.*)/$', views.MarketplaceHome.as_view(), name='marketplace-home-status'),
    url(r'^marketplace-send/$', views.MarketplaceSend.as_view(), name='marketplace-send'),
    url(r'^settings-user/$', views.SettingsUser.as_view(), name='settings-user'),
    url(r'^settings-vendor/$', views.SettingsVendor.as_view(), name='settings-vendor'),
    url(r'^settings-marketplace/$', views.SettingsMarketplace.as_view(), name='settings-marketplace'),
    url(r'^support/$', views.CustomerSupportView.as_view(), name='cust-support'),
    url(r'^transaction-confirmed/(?P<tr_amount>\d+\.\d{2})/(?P<amount>\d+\.\d{2})/(?P<sender_name>.*)/(?P<recipient_name>.*)/(?P<tr_type>\w+)$', views.TransactionConfirmedView.as_view(), name='transaction-confirmed'),
    url(r'^vendor-assign-users/(?P<vendor_id>\d+)/$', views.VendorAssign.as_view(), name='vendor-assign-users'),
    url(r'^vendor-initial/$', views.VendorInitial.as_view(), name='vendor-initial'),
    url(r'^vendor-cust-login/(?P<status_msg>.*)/$', views.VendorCustLogin.as_view(), name='vendor-cust-login'),
    url(r'^vendor-choose-payment/$', views.VendorChoosePayment.as_view(), name='vendor-choose-payment'),
    url(r'^vendor-home/$', views.VendorHome.as_view(), name='vendor-home'),
    url(r'^vendor-transaction/$', views.VendorTransaction.as_view(), name='vendor-transaction'),
    url(r'^user-home/$', views.UserHomeView.as_view(), name='user-home'),
    url(r'^user-home/(?P<status_msg>.*)/$', views.UserHomeView.as_view(), name='user-home-status'),
    url(r'^500/$', views.ErrorView.as_view(), name='500'),
    url(r'^404/$', views.NotFoundView.as_view(), name='404'),

    # functional views
    url(r'^assign_credit_to_user/$', views.assign_credit_to_user, name='assign_credit_to_user'),
    url(r'^create_user/$', views.create_user, name='create_user'),
    url(r'^create_vendor/$', views.create_vendor, name='create_vendor'),
    url(r'^entity_assign_users/(?P<entity_id>\d+)$', views.entity_assign_users, name='entity_assign_users'),
    url(r'^export_data/$', views.export_data, name='export_data'),
    url(r'^process_cust_login/(?P<login_reason>(issue_credit|transaction))$', views.process_cust_login, name='process_cust_login'),
    url(r'^process_login/$', views.process_login, name='process_login'),
    url(r'^process_logout/$', views.process_logout, name='process_logout'),
    url(r'^process_vendor_payment/$', views.process_vendor_payment, name='process_vendor_payment'),
    url(r'^process_vendor_transaction/$', views.process_vendor_transaction, name='process_vendor_transaction'),
    url(r'^record_venue/(?P<venue_id>\d+)/$', views.record_venue, name='record_venue'),
    url(r'^redeem_credits/$', views.redeem_credits, name='redeem_credits'),
    url(r'^redirect_to_vendor/$', views.redirect_to_vendor, name='redirect_to_vendor'),
    url(r'^redirect_to_marketplace/$', views.redirect_to_marketplace, name='redirect_to_marketplace'),
]

handler404 = 'tradewave.views.return_404'
handler500 = 'mysite.views.my_custom_error_view'
#handler403 = 'mysite.views.my_custom_permission_denied_view'
#handler400 = 'mysite.views.my_custom_bad_request_view'
