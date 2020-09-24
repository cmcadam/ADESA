from django.contrib import admin
from .models import Employee, Organisation, Audit, Report, Score

admin.site.register(Employee)
admin.site.register(Organisation)
admin.site.register(Audit)
admin.site.register(Report)
admin.site.register(Score)
