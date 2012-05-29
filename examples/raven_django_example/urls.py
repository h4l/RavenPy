from django.conf.urls.defaults import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', 'raven_django_example.app.views.home', name='home'),
    url(r'^private/$', 'raven_django_example.app.views.private', name='private'),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^accounts/login/', 'raven.raven_django.views.raven_login'),

)
