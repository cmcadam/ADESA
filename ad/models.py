from django.db import models
from django.contrib.auth.models import User


class Server(models.Model):
    owner = models.ForeignKey(User, models.CASCADE)
    name = models.CharField(max_length=50)
    server_address = models.CharField(max_length=20)
    ssh_port = models.IntegerField(default=22)
    # server_username = models.CharField(max_length=50)
    save_server_details = models.BooleanField(default=False)
    save_reports = models.BooleanField(default=True)
    share_reports = models.BooleanField(default=True)


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
    server = models.ForeignKey(Server, on_delete=models.CASCADE)
    score = models.ForeignKey(Score, on_delete=models.CASCADE)
    date_created = models.DateField()
    report_file = models.FileField()


class Audit(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)


# class Employee(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     server = models.ForeignKey(Server, on_delete=models.CASCADE)