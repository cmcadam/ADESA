from django.contrib import admin
from .models import Server, Audit, Report, Score

# admin.site.register(Employee)
admin.site.register(Server)
admin.site.register(Audit)
admin.site.register(Report)
admin.site.register(Score)
