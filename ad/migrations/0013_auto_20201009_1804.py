# Generated by Django 3.1.1 on 2020-10-09 07:04

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ad', '0012_auto_20201009_1751'),
    ]

    operations = [
        migrations.AlterField(
            model_name='server',
            name='shared_with',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='shared_with', to=settings.AUTH_USER_MODEL),
        ),
    ]
