from django.urls import path
from ad import views
urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('configuration/', views.configuration, name='configuration'),
    path('auditor/', views.auditor, name='auditor'),
    path('add-server/', views.add_server, name='add_server')
]