# -*- coding: utf-8 -*-
# Generated by Django 1.9.2 on 2016-02-15 05:55
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('tradewave', '0003_auto_20160215_0116'),
    ]

    operations = [
        migrations.AddField(
            model_name='entity',
            name='user_tradewave',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='tradewave.TradewaveUser'),
        ),
    ]
