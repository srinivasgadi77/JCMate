# Generated by Django 2.0.7 on 2019-06-28 19:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixit', '0011_auto_20190628_1909'),
    ]

    operations = [
        migrations.AlterField(
            model_name='hostlist',
            name='DateTime',
            field=models.DateTimeField(blank=True, default='2019-06-28 19:14:33'),
        ),
    ]
