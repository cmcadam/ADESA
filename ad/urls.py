from django.urls import path
from ad import views
urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('configuration/', views.configuration, name='configuration'),
    path('auditor/', views.auditor, name='auditor'),
    path('auditor/authorize/<str:pk>/', views.authorize_audit, name='authorize_audit'),
    path('audit/details/<str:pk>/', views.audit_details, name='audit_details'),
    path('add-server/', views.add_server, name='add_server'),
    path('generate-report/<str:pk>', views.generate_report, name='generate_report'),
    path('edit/<str:pk>', views.edit_server, name='edit_server'),
    path('remove/<str:pk>', views.remove_server, name='remove_server'),
    path('send-results/<str:pk>', views.send_results, name='send_results')
]