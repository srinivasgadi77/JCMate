# Generated by Django 2.0.7 on 2019-06-28 17:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixit', '0008_hostlist_datetime'),
    ]

    operations = [
        migrations.AlterField(
            model_name='hostlist',
            name='DateTime',
            field=models.DateTimeField(blank=True, default='28-06-2019 17:06:57'),
        ),
    ]
