# Generated by Django 3.0.7 on 2020-11-27 14:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0002_vulnerabilityseverityscore'),
    ]

    operations = [
        migrations.CreateModel(
            name='VulnerabilitySeverity',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('severity_type', models.CharField(help_text='Example: CVSS v2, Redhat Impact Score', max_length=50)),
                ('severity_value', models.CharField(help_text='Example: 9.0, Important, High', max_length=50)),
                ('reference', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vulnerabilities.VulnerabilityReference')),
                ('vulnerability', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vulnerabilities.Vulnerability')),
            ],
        ),
        migrations.DeleteModel(
            name='VulnerabilitySeverityScore',
        ),
    ]
