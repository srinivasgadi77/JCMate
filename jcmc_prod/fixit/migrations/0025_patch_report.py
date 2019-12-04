# Generated by Django 2.0.7 on 2019-09-16 12:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixit', '0024_scheduledjobs_invalidhosts'),
    ]

    operations = [
        migrations.CreateModel(
            name='patch_report',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pre_cves_important', models.CharField(default=' ', max_length=100)),
                ('pre_cves_critical', models.CharField(default=' ', max_length=100)),
                ('post_cves_critical', models.CharField(default=' ', max_length=100)),
                ('owner_email', models.CharField(default=' ', max_length=100)),
                ('pre_cves_low', models.CharField(default=' ', max_length=100)),
                ('pre_kernel', models.CharField(default=' ', max_length=100)),
                ('pre_os_version', models.CharField(default=' ', max_length=100)),
                ('cves_pending', models.CharField(default=' ', max_length=100)),
                ('cves_status', models.CharField(default=' ', max_length=100)),
                ('snapshot_date', models.CharField(default=' ', max_length=100)),
                ('uptrack_status', models.CharField(default=' ', max_length=100)),
                ('upgraded_kernel', models.CharField(default=' ', max_length=100)),
                ('pre_cves_moderate', models.CharField(default=' ', max_length=100)),
                ('date_patched', models.CharField(default=' ', max_length=100)),
                ('non_uek_status', models.CharField(default=' ', max_length=100)),
                ('kernel_status', models.CharField(default=' ', max_length=100)),
                ('reboot_status', models.CharField(default=' ', max_length=100)),
                ('host_name', models.CharField(default=' ', max_length=100)),
                ('post_cves_moderate', models.CharField(default=' ', max_length=100)),
                ('updated_os_version', models.CharField(default=' ', max_length=100)),
                ('post_cves_important', models.CharField(default=' ', max_length=100)),
            ],
            options={
                'verbose_name': 'CpuPatchData',
            },
        ),
    ]