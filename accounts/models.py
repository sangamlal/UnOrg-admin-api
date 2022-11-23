
from enum import unique
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone  
from django.utils.translation import gettext_lazy as _  
 
# Create your models here.

class User(AbstractUser):
    
    mobile=models.CharField(_("Mobile") ,max_length=15)
    is_zoho_active=models.IntegerField(default=0)
    latitude=models.CharField(max_length=200)
    longitude=models.CharField(max_length=200)
    def __str__(self) :
        return self.username


class zohoaccount(models.Model):
    userid =models.ForeignKey(User, on_delete=models.CASCADE)
    clientid=models.CharField(max_length=100)
    clientsecret=models.CharField(max_length=200)
    accesstoken=models.CharField(max_length=400)
    refreshtoken=models.CharField(max_length=400)
    redirecturi=models.CharField(max_length=400)
    is_deleted=models.BooleanField(default=0)
    created_at=models.DateTimeField(auto_now=True)
    # def __str__(self) :
    #     return (self.id,self.clientid,self.userid,self.clientsecret,self.accesstoken,self.refreshtoken,self.redirecturi,self.is_deleted,self.created_at)


class vehicleinfo(models.Model):
    userid =models.ForeignKey(User, on_delete=models.CASCADE)
    password=models.CharField(max_length=100)
    vehiclename=models.CharField(max_length=200)
    maxorders=models.CharField(max_length=400)
    weightcapacity=models.CharField(max_length=400)
    phone=models.CharField(max_length=400)
    is_deleted=models.BooleanField(default=0)
    created_at=models.DateTimeField(auto_now=True)
class slotinfo(models.Model):
    userid =models.ForeignKey(User, on_delete=models.CASCADE)
    slottime=models.CharField(max_length=100)
    is_deleted=models.BooleanField(default=0)
    created_at=models.DateTimeField(auto_now=True)
    created_at=models.DateTimeField(auto_now=True)
class iteminfo(models.Model):
    userid =models.ForeignKey(User, on_delete=models.CASCADE)
    zoho_item_id=models.CharField(max_length=100)
    item_name=models.CharField(max_length=100)
    item_waight=models.FloatField(default=0)
    created_at=models.DateTimeField(auto_now=True)
    is_deleted=models.BooleanField(default=0)
    updated_at=models.DateTimeField(auto_now=True)


class orderinfo(models.Model):
    userid =models.ForeignKey(User, on_delete=models.CASCADE)
    shipping_address=models.CharField(max_length=400)
    invoice_id=models.CharField(max_length=200)
    customer_id=models.CharField(max_length=200)
    weight =models.IntegerField()
    customer_name=models.CharField(max_length=200)
    invoice_number=models.CharField(max_length=200)
    invoice_total=models.CharField(max_length=200)
    invoice_balance=models.CharField(max_length=200)
    time_slot=models.CharField(max_length=200)
    contactno=models.CharField(max_length=200)

    location_coordinates=models.CharField(max_length=200)
    is_coordinate=models.BooleanField(default=0)
    is_deleted=models.BooleanField(default=0)
    updated_at=models.DateTimeField(auto_now=True)
    created_date=models.DateTimeField(auto_now=True)

class ordersdelivery(models.Model):
    order_id = models.ForeignKey(orderinfo,on_delete = models.CASCADE)
    vehicle_id = models.ForeignKey(vehicleinfo,on_delete=models.CASCADE)
    time_slot=models.CharField(max_length=30,null=True,blank=True)
    user_id = models.ForeignKey(User,on_delete=models.CASCADE)
    customer_name = models.CharField(max_length=30,null=True,blank=True)
    phone_number = models.CharField(max_length=30,null=True,blank=True)
    email =models.CharField(max_length=30,null=True,blank=True)
    latitude = models.CharField(max_length=30,null=True,blank=True)
    longitude = models.CharField(max_length=30,null=True,blank=True)
    weight = models.FloatField(default=0)
    location = models.CharField(max_length=50,null=True,blank=True)
    collectedAmount = models.FloatField(default=0) 
    orderValue = models.CharField(max_length=50,null=True,blank=True)
    invoiceNo = models.CharField(max_length=50,null=True,blank=True)
    invoiceID = models.CharField(max_length=50,null=True,blank=True)
    status = models.CharField(max_length=30,null=True,blank=True ,default='pending')
    upi = models.FloatField(default=0)
    cash = models.FloatField(default=0)
    other = models.FloatField(default=0)
    reason = models.CharField(max_length=200,null=True,blank=True)
    is_deleted = models.BooleanField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
    created_date = models.DateTimeField(auto_now=True)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .helper import get_model_fields
        self.output_fields = get_model_fields(ordersdelivery)
    
    def convert_to_output_format(self,qs_json):
        meta_fields = ordersdelivery._meta.get_fields()
        fields = [f.name for f in meta_fields]
        primary_key_name = ordersdelivery._meta.pk.name

        final_result = []

        for item in qs_json:
            entity_details = {}
            if item.get('fields') is None:
                continue
            for f in fields:
                entity_details[f] = item['fields'].get(f)
            entity_details[primary_key_name] = item.get('pk')
            for f in item.keys():
                if f == 'fields':
                    continue
                entity_details[f] = item.get(f)
            final_result.append(entity_details)
        return final_result