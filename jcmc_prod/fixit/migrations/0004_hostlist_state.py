# Generated by Django 2.0.7 on 2019-06-28 08:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixit', '0003_remove_hostlist_state'),
    ]

    operations = [
        migrations.AddField(
            model_name='hostlist',
            name='state',
            field=models.CharField(default='UnKnown', max_length=50),
        ),
    ]