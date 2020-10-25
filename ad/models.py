from django.db import models
from django.contrib.auth.models import User

from jsonfield import JSONField


class Server(models.Model):
    owner = models.ForeignKey(User, models.CASCADE)
    name = models.CharField(max_length=50)
    server_address = models.CharField(max_length=20)
    ssh_port = models.IntegerField(default=22)
    save_reports = models.BooleanField(default=True)
    share_reports = models.BooleanField(default=True)
    shared_with = models.ForeignKey(User, models.CASCADE, related_name='shared_with', null=True, blank=True)


class Report(models.Model):
    server = models.ForeignKey(Server, on_delete=models.CASCADE)
    json_report = JSONField()
    date_created = models.DateTimeField(auto_now_add=True)
    report_file = models.FileField()


class Audit(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)