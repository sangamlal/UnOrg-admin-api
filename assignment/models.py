from django.db import models

# Create your models here.


class Items(models.Model):
    item_name = models.CharField(max_length=30)
    item_quantity = models.IntegerField(default=0)
    item_unit = models.IntegerField(default=0)
    item_weight = models.FloatField(default=0)