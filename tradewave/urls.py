from django.conf.urls import patterns, url

from tradewave import views

urlpatterns = patterns('',
    url(r'^$', views.LoginView.as_view(), name='login'),
    url(r'^login/$', views.LoginView.as_view(), name='login'),
    url(r'^home-user/$', views.HomeUserView.as_view(), name='home-user'),
    url(r'^send/$', views.SendView.as_view(), name='send'),
    url(r'^confirm-send/$', views.ConfirmSendView.as_view(), name='confirm-send'),
    url(r'^confirm-receive/$', views.ConfirmReceiveView.as_view(), name='confirm-receive'),
    url(r'^transaction-confirmed/$', views.TransactionConfirmedView.as_view(), name='transaction-confirmed'),
	url(r'^create-user/$', views.CreateUserView.as_view(), name='create-user'),
	url(r'^create-vendor/$', views.CreateVendorView.as_view(), name='create-vendor'),
	url(r'^load-ddip/$', views.LoadDdipView.as_view(), name='load-ddip')
)

