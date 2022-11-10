
from enum import unique
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone  
from django.utils.translation import gettext_lazy as _  
 
# Create your models here.

class User(AbstractUser):
    
    mobile=models.CharField(_("Mobile") ,max_length=15)

    def __str__(self) :
        return self.username


class zohoaccount(models.Model):
    userid =models.IntegerField()
    clientid=models.CharField(max_length=100)
    clientsecret=models.CharField(max_length=200)
    accesstoken=models.CharField(max_length=400)
    refreshtoken=models.CharField(max_length=400)
    redirecturi=models.CharField(max_length=400)
    is_deleted=models.BooleanField(default=0)
    created_at=models.DateTimeField(auto_now=True)
    # def __str__(self) :
    #     return (self.id,self.clientid,self.userid,self.clientsecret,self.accesstoken,self.refreshtoken,self.redirecturi,self.is_deleted,self.created_at)

