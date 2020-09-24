from django.db import models
from django.contrib.auth.models import User


class Organisation(models.Model):
    name = models.CharField(max_length=50)
    server_address = models.CharField(max_length=20)
    ssh_port = models.IntegerField(default=22)
    server_username = models.CharField(max_length=50)


class Score(models.Model):
    application_control = models.IntegerField()
    patching_applications = models.IntegerField()
    office_macros = models.IntegerField()
    application_hardening = models.IntegerField()
    admin_privileges = models.IntegerField()
    patching_os = models.IntegerField()
    multifactor_auth = models.IntegerField()
    backups = models.IntegerField()


class Report(models.Model):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE)
    score = models.ForeignKey(Score, on_delete=models.CASCADE)
    date_created = models.DateField()
    report_file = models.FileField()


class Audit(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)


class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE)
    save_reports = models.BooleanField(default=True)
    save_credentials = models.BooleanField(default=True)