# Generated by Django 4.1.3 on 2022-11-29 06:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_rename_invoiceid_ordersdelivery_invoice_balance_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderinfo',
            name='location_url',
            field=models.CharField(default='', max_length=400),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='zohoaccount',
            name='clientid',
            field=models.CharField(blank=True, max_length=100, unique=True),
        ),
    ]
