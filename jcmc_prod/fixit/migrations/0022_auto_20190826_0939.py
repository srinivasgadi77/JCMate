# Generated by Django 2.0.7 on 2019-08-26 09:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('fixit', '0021_auto_20190826_0935'),
    ]

    operations = [
        migrations.RenameField(
            model_name='scheduledjobs',
            old_name='running_coount',
            new_name='running_count',
        ),
    ]
