# Generated by Django 3.1.1 on 2020-10-05 12:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ad', '0010_auto_20201005_1820'),
    ]

    operations = [
        migrations.AlterField(
            model_name='report',
            name='date_created',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
