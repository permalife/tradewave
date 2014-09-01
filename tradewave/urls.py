from django.conf.urls import patterns, url

from tradewave import views

urlpatterns = patterns('',
    url(r'^$', views.LoginView.as_view(), name='login'),
    url(r'^login/$', views.LoginView.as_view(), name='login'),
    url(r'^user-home/$', views.UserHomeView.as_view(), name='user-home'),
    url(r'^send/$', views.SendView.as_view(), name='send'),
    url(r'^confirm-send/$', views.ConfirmSendView.as_view(), name='confirm-send'),
    url(r'^confirm-receive/$', views.ConfirmReceiveView.as_view(), name='confirm-receive'),
    url(r'^transaction-confirmed/$', views.TransactionConfirmedView.as_view(), name='transaction-confirmed'),
    url(r'^create-user/$', views.CreateUserView.as_view(), name='create-user'),
    url(r'^create-vendor/$', views.CreateVendorView.as_view(), name='create-vendor'),
    url(r'^load-DDIP/$', views.LoadDdipView.as_view(), name='load-ddip'),
    url(r'^marketplace-initial/$', views.MarketplaceInitial.as_view(), name='marketplace-initial'),
    url(r'^marketplace-issue/$', views.MarketplaceIssue.as_view(), name='marketplace-issue'),
    url(r'^marketplace-home/$', views.MarketplaceHome.as_view(), name='marketplace-home'),
    url(r'^marketplace-send/$', views.MarketplaceSend.as_view(), name='marketplace-send'),
    url(r'^vendor-initial/$', views.VendorInitial.as_view(), name='vendor-initial'),
    url(r'^vendor-cust-login/$', views.VendorCustLogin.as_view(), name='vendor-cust-login'),
    url(r'^vendor-choose-payment/$', views.VendorChoosePayment.as_view(), name='vendor-choose-payment'),
    url(r'^vendor-home/$', views.VendorHome.as_view(), name='vendor-home'),
    url(r'^vendor-transaction/$', views.VendorTransaction.as_view(), name='vendor-transaction'),
    url(r'^process_login/$', views.process_login, name='process_login'),
    url(r'^record_venue/(?P<venue_id>\d+)/$', views.record_venue, name='record_venue')
)

