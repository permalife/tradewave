from django.conf.urls import url

from tradewave import views

urlpatterns = [
    # template views
    url(r'^$', views.LoginView.as_view(), name='root'),
    url(r'^login/(?P<status_msg>.*)/$', views.LoginView.as_view(), name='login'),
    url(r'^send/$', views.SendView.as_view(), name='send'),
    url(r'^confirm-send/$', views.ConfirmSendView.as_view(), name='confirm-send'),
    url(r'^confirm-receive/$', views.ConfirmReceiveView.as_view(), name='confirm-receive'),
    url(r'^create-user/$', views.CreateUserView.as_view(), name='create-user'),
    url(r'^create-vendor/$', views.CreateVendorView.as_view(), name='create-vendor'),
    url(r'^dashboard/$', views.DashboardView.as_view(), name='dashboard'),
    url(r'^export_data/$', views.export_data, name='export_data'),
    url(r'^load-ddip/$', views.LoadDdipView.as_view(), name='load-ddip'),
    url(r'^marketplace-initial/$', views.MarketplaceInitial.as_view(), name='marketplace-initial'),
    url(r'^marketplace-issue/$', views.MarketplaceIssue.as_view(), name='marketplace-issue'),
    url(r'^marketplace-issue-login/$', views.MarketplaceIssueLogin.as_view(), name='marketplace-issue-login'),
    url(r'^marketplace-issue-new/(?P<status_msg>.*)/$', views.MarketplaceIssueNew.as_view(), name='marketplace-issue-new'),
    url(r'^marketplace-issue-pick-credit/$', views.MarketplaceIssuePickCredit.as_view(), name='marketplace-issue-pick-credit'),
    url(r'^marketplace-redeem/$', views.MarketplaceRedeem.as_view(), name='marketplace-redeem'),
    url(r'^marketplace-home/$', views.MarketplaceHome.as_view(), name='marketplace-home'),
    url(r'^marketplace-send/$', views.MarketplaceSend.as_view(), name='marketplace-send'),
    url(r'^settings-user/$', views.SettingsUser.as_view(), name='settings-user'),
    url(r'^settings-vendor/$', views.SettingsVendor.as_view(), name='settings-vendor'),
    url(r'^settings-marketplace/$', views.SettingsMarketplace.as_view(), name='settings-marketplace'),
    url(r'^support/$', views.CustomerSupportView.as_view(), name='cust-support'),
    url(r'^transaction-confirmed/(?P<tr_amount>\d+\.\d{2})/(?P<amount>\d+\.\d{2})/(?P<sender_name>.*)/(?P<recipient_name>.*)/(?P<tr_type>\w+)$', views.TransactionConfirmedView.as_view(), name='transaction-confirmed'),
    url(r'^vendor-initial/$', views.VendorInitial.as_view(), name='vendor-initial'),
    url(r'^vendor-cust-login/(?P<status_msg>.*)/$', views.VendorCustLogin.as_view(), name='vendor-cust-login'),
    url(r'^vendor-choose-payment/$', views.VendorChoosePayment.as_view(), name='vendor-choose-payment'),
    url(r'^vendor-home/$', views.VendorHome.as_view(), name='vendor-home'),
	url(r'^cust-support/$', views.CustSupport.as_view(), name='cust-support'),
    url(r'^vendor-transaction/$', views.VendorTransaction.as_view(), name='vendor-transaction'),
    url(r'^user-home/$', views.UserHomeView.as_view(), name='user-home'),

    # functional views
    url(r'^assign_credit_to_user/$', views.assign_credit_to_user, name='assign_credit_to_user'),
    url(r'^create_user/$', views.create_user, name='create_user'),
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

#handler404 = 'mysite.views.my_custom_page_not_found_view'
#handler500 = 'mysite.views.my_custom_error_view'
#handler403 = 'mysite.views.my_custom_permission_denied_view'
#handler400 = 'mysite.views.my_custom_bad_request_view'
