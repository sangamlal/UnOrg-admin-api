# Generated by Django 4.1.3 on 2022-12-06 10:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_ordersdelivery_serialno'),
    ]

    operations = [
        migrations.AddField(
            model_name='ordersdelivery',
            name='is_priority_change',
            field=models.BooleanField(default=0),
        ),
        migrations.AddField(
            model_name='ordersdelivery',
            name='is_vehicle_update',
            field=models.BooleanField(default=0),
        ),
        migrations.AddField(
            model_name='vehicleinfo',
            name='is_vehicle_not_available',
            field=models.BooleanField(default=0),
        ),
    ]
