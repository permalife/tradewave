# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-07-05 08:22
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tradewave', '0012_auto_20160705_0743'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tradewaveuser',
            name='qr_string',
            field=models.CharField(max_length=1024),
        ),
    ]
