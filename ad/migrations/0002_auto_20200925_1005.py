# Generated by Django 3.1.1 on 2020-09-25 00:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='employee',
            name='save_credentials',
        ),
        migrations.RemoveField(
            model_name='employee',
            name='save_reports',
        ),
        migrations.AddField(
            model_name='organisation',
            name='save_credentials',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='organisation',
            name='save_reports',
            field=models.BooleanField(default=True),
        ),
    ]
