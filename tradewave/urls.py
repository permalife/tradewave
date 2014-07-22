from django.conf.urls import patterns, url

from tradewave import views

urlpatterns = patterns('',
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^login/$', views.LoginView.as_view(), name='login'),
    url(r'^home-user/$', views.HomeUserView.as_view(), name='home-user'),
    url(r'^send/$', views.SendView.as_view(), name='send'),
    url(r'^confirm-send/$', views.ConfirmSendView.as_view(), name='confirm-send'),
    url(r'^confirm-receive/$', views.ConfirmReceiveView.as_view(), name='confirm-receive'),
    url(r'^transaction-confirmed/$', views.TransactionConfirmedView.as_view(), name='transaction-confirmed')
)

