# Generated by Django 3.1.1 on 2020-10-05 03:56

from django.db import migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('ad', '0008_auto_20201005_1439'),
    ]

    operations = [
        migrations.AlterField(
            model_name='testclass',
            name='test',
            field=jsonfield.fields.JSONField(),
        ),
    ]