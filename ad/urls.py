from django.urls import path
from ad import views
urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('configuration/', views.configuration, name='configuration'),
    path('auditor/', views.auditor, name='auditor'),
    path('auditor/authorize/<str:id>/', views.authorize_audit, name='authorize_audit'),
    path('audit/details/<str:id>/', views.audit_details, name='audit_details'),
    path('add-server/', views.add_server, name='add_server')
]