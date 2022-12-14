
from enum import unique
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone  
from django.utils.translation import gettext_lazy as _  
 
# Create your models here.

class Branches(models.Model):
    zoho_branch_id = models.CharField(max_length=50,unique=True)
    branch_name = models.CharField(max_length=20,null=True,blank=True)
    branch_email = models.EmailField(max_length=30)
    is_deleted=models.BooleanField(default=0)
    created_at=models.DateTimeField(auto_now=True)
    updated_at=models.DateTimeField(auto_now=True)

class User(AbstractUser):
    
    mobile=models.CharField(_("Mobile") ,max_length=15)
    is_zoho_active=models.IntegerField(default=0)
    latitude=models.CharField(max_length=200)
    longitude=models.CharField(max_length=200)
    branch_id = models.ForeignKey(Branches,on_delete=models.CASCADE)
    def __str__(self) :
        return self.username


class zohoaccount(models.Model):
    userid =models.ForeignKey(User, on_delete=models.CASCADE)
    clientid=models.CharField(max_length=100,unique=True,blank=True)
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
    is_vehicle_not_available=models.BooleanField(default=0)
class slotinfo(models.Model):
    userid =models.ForeignKey(User, on_delete=models.CASCADE)
    slottime=models.CharField(max_length=100)
    is_deleted=models.BooleanField(default=0)
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
    location_url=models.CharField(max_length=400)
    is_coordinate=models.BooleanField(default=0)
    is_deleted=models.BooleanField(default=0)
    updated_at=models.DateTimeField(auto_now=True)
    created_date=models.DateTimeField(auto_now=True)
    zoho_updated_time = models.CharField(max_length=50)

class ordersdelivery(models.Model):
    order_id = models.ForeignKey(orderinfo,on_delete = models.CASCADE)
    vehicle_id = models.ForeignKey(vehicleinfo,on_delete=models.CASCADE)
    time_slot=models.CharField(max_length=30,null=True,blank=True)
    user_id = models.ForeignKey(User,on_delete=models.CASCADE)
    customer_name = models.CharField(max_length=30,null=True,blank=True)
    phone_number = models.CharField(max_length=30,null=True,blank=True)
    email =models.CharField(max_length=30,null=True,blank=True)
    location_coordinates = models.CharField(max_length=250,null=True,blank=True)
    location_url = models.CharField(max_length=255,null=True,blank=True)
    weight = models.FloatField(default=0)
    serialno = models.IntegerField(default=0)
    shipping_address = models.CharField(max_length=250,null=True,blank=True)
    collectedAmount = models.FloatField(default=0) 
    invoice_total = models.CharField(max_length=50,null=True,blank=True)
    invoice_balance = models.CharField(max_length=50,null=True,blank=True)
    invoice_number = models.CharField(max_length=50,null=True,blank=True)
    invoice_id = models.CharField(max_length=50,null=True,blank=True)
    status = models.CharField(max_length=30,null=True,blank=True ,default='pending')
    upi = models.FloatField(default=0)
    cash = models.FloatField(default=0)
    other = models.FloatField(default=0)
    reason = models.CharField(max_length=200,null=True,blank=True)
    is_deleted = models.BooleanField(default=0)
    is_published = models.BooleanField(default=0)
    is_manually_assigned=models.BooleanField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
    created_date = models.DateTimeField(auto_now=True)
    is_vehicle_update=models.BooleanField(default=0)
    is_priority_change=models.BooleanField(default=0)
    trip_count=models.IntegerField(default=0)