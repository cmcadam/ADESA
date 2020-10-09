from django.contrib import admin
from .models import Server, Audit, Report

# admin.site.register(Employee)
admin.site.register(Server)
admin.site.register(Audit)
admin.site.register(Report)
