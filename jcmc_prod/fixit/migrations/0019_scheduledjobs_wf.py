# Generated by Django 2.0.7 on 2019-08-22 11:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixit', '0018_scheduledjobs'),
    ]

    operations = [
        migrations.AddField(
            model_name='scheduledjobs',
            name='WF',
            field=models.CharField(blank=True, max_length=50),
        ),
    ]
