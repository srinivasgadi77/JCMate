# Generated by Django 2.0.7 on 2019-06-28 17:43

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixit', '0007_auto_20190628_0851'),
    ]

    operations = [
        migrations.AddField(
            model_name='hostlist',
            name='DateTime',
            field=models.DateTimeField(blank=True, default=datetime.datetime.now),
        ),
    ]
