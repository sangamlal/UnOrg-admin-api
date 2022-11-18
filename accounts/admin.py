from django.contrib import admin
from django.contrib.auth.admin import UserAdmin


from accounts.models import User
# Register your models here.

from .models import *
class CustomeUserAdmin(UserAdmin):
    model = User

# admin.site.unregister(User)
admin.site.register(User,CustomeUserAdmin)

admin.site.register(ordersdelivery)
