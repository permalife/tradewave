# -*- coding: utf-8 -*-
# Generated by Django 1.10.3 on 2017-01-29 07:48
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tradewave', '0016_auto_20161222_0520'),
    ]

    operations = [
        migrations.AddField(
            model_name='token',
            name='is_marketplace',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='token',
            name='is_vendor',
            field=models.BooleanField(default=False),
        ),
    ]