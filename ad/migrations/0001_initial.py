# Generated by Django 3.1.1 on 2020-09-24 07:55

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Organisation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('server_address', models.CharField(max_length=20)),
                ('ssh_port', models.IntegerField(default=22)),
                ('server_username', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='Score',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('application_control', models.IntegerField()),
                ('patching_applications', models.IntegerField()),
                ('office_macros', models.IntegerField()),
                ('application_hardening', models.IntegerField()),
                ('admin_privileges', models.IntegerField()),
                ('patching_os', models.IntegerField()),
                ('multifactor_auth', models.IntegerField()),
                ('backups', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_created', models.DateField()),
                ('report_file', models.FileField(upload_to='')),
                ('organisation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ad.organisation')),
                ('score', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ad.score')),
            ],
        ),
        migrations.CreateModel(
            name='Employee',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('save_reports', models.BooleanField(default=True)),
                ('save_credentials', models.BooleanField(default=True)),
                ('organisation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ad.organisation')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ad.report')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]