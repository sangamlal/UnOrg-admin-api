# Generated by Django 3.2.8 on 2022-11-09 20:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_user_mobile'),
    ]

    operations = [
        migrations.CreateModel(
            name='zohoaccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userid', models.IntegerField()),
                ('clientid', models.CharField(max_length=100)),
                ('clientsecret', models.CharField(max_length=200)),
                ('accesstoken', models.CharField(max_length=400)),
                ('refreshtoken', models.CharField(max_length=400)),
                ('is_deleted', models.BooleanField(default=0)),
                ('created_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]