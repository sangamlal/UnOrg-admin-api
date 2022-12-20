
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

from .models import *


# UserCreate without override create method--------------
class SignupUserSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(required=True, validators=[
                                   UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(
        required=True, write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'confirm_password',
                  'email', 'first_name', 'last_name', 'mobile','branch_id')
        # extra_kwargs={"confirm_password":{'write_only':True}}

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError(
                {'password': "password and confirm_password did'nt match."})
        return attrs


class UserLoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['username', 'password']


class SendZohoRegistrationLinkSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    userid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'


class EditUserProfileSerializer(serializers.Serializer):

    id = serializers.CharField(required=True)
    email = serializers.EmailField(required=False, allow_blank=True, allow_null=True)
    username = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    first_name = serializers.CharField(
        required=False, allow_blank=True, allow_null=True)
    last_name = serializers.CharField(
        required=False, allow_blank=True, allow_null=True)
    mobile = serializers.CharField(
        required=False, allow_blank=True, allow_null=True)

    class Meta:
        fields = '__all__'


class GetUserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'mobile', 'email']


class ZohoAccountSerializer(serializers.ModelSerializer):
    zohoaccountid = serializers.CharField(required=True)
    class Meta:
        model = zohoaccount
        fields = ['zohoaccountid', 'clientid', 'clientsecret', 'redirecturi']


class EditZohoAccountSerializer(serializers.Serializer):

    id = serializers.CharField(required=True)
    code = serializers.CharField(
        required=False, allow_blank=True, allow_null=True)

    class Meta:
        fields = '__all__'
class GetZohoCredentialSerializer(serializers.Serializer):

    userid = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'


class SendRedirectUriEmailSerializer(serializers.Serializer):

    zohoaccountid = serializers.CharField(required=True)
    
    class Meta:
        fields = '__all__'


class VehicleRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = vehicleinfo
        fields = ['userid', 'password', 'vehiclename', 'maxorders', 'weightcapacity', 'phone']

class EditVehicleRegistrationSerializer(serializers.ModelSerializer):
    vehicleinfoid = serializers.CharField(required=True)
    class Meta:
        model = vehicleinfo
        fields = ['vehicleinfoid',  'vehiclename', 'maxorders', 'weightcapacity', 'phone']

class VehicleLoginSerializer(serializers.Serializer):
    vehicleinfoid = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'
class GetVehicleDetailSerializer(serializers.Serializer):
    vehicleinfoid = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'
class GetVehicleListSerializer(serializers.Serializer):
    userid = serializers.CharField(required=True)
    type = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    # slotid = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'


class AddSlotSerializer(serializers.ModelSerializer):
    class Meta:
        model = slotinfo
        fields = ['userid', 'slottime']
class EditSlotSerializer(serializers.ModelSerializer):
    slotid = serializers.CharField(required=True)
    class Meta:
        model = slotinfo
        fields = ['slotid','slottime']


class GetSlotListSerializer(serializers.Serializer):
    userid = serializers.CharField(required=True)
    slotinfoid = serializers.CharField(required=False,allow_blank=True, allow_null=True)
    class Meta:
        fields = '__all__'

class GetSlotDetailSerializer(serializers.Serializer):
    slotinfoid = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'


class AddcordinatesSerializer(serializers.Serializer):
    latitude = serializers.CharField(required=True)
    longitude = serializers.CharField(required=True)
    userid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'

class GetItemDetailSerializer(serializers.Serializer):
    iteminfoid = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'

class EditItemDetailSerializer(serializers.Serializer):
    iteminfoid = serializers.CharField(required=True)
    item_waight = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'

class GetOrderbySlotDetailSerializer(serializers.Serializer):
    userid = serializers.CharField(required=True)
    slotid = serializers.CharField(required=True)
    # coordinate_type = serializers.CharField(required=True)
    class Meta:
        fields = '__all__'
class GetOrderbyfororderListSlotDetailSerializer(serializers.Serializer):
    userid = serializers.CharField(required=True)
    slotid = serializers.CharField(required=True)
    type = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    class Meta:
        fields = '__all__'


class orders_delivery_serializers(serializers.ModelSerializer):
    id = serializers.CharField(required=True)
    class Meta:
        model = ordersdelivery
        fields = ['id','order_id' ,'vehicle_id','collectedAmount','status','upi','cash','other','reason'] 

class GetOrderDetailSerializer(serializers.Serializer):
    vehicleid = serializers.CharField(required=True)
    ordersdeliveryid = serializers.CharField(required=True)
    class Meta:
        fields = '_all_'

class GetOrderListSerializer(serializers.Serializer):
    vehicleid = serializers.CharField(required=True)
    class Meta:
        fields = '_all_'


class AssignOrdertoVehicleSerializer(serializers.Serializer):
    vehicleid = serializers.CharField(required=True)
    orderid = serializers.CharField(required=True)
    userid = serializers.CharField(required=True)
    invoiceid = serializers.CharField(required=True)
    slotid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'

class EditAssignOrdertoVehicleSerializer(serializers.Serializer):
    # ordersdeliveryid = serializers.CharField(required=True)
    vehicleid = serializers.CharField(required=True)
    orderid = serializers.CharField(required=True)
    userid = serializers.CharField(required=True)
    invoiceid = serializers.CharField(required=True)
    slotid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'


class AssignSerialNumberToOrdersSerializer(serializers.Serializer):
    # ordersdeliveryid = serializers.CharField(required=True)
    userid = serializers.CharField(required=True)
    listofinvoiceid_serialno = serializers.CharField(required=True)
    slotid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'
    
class HistoryGetSlotListSerializer(serializers.Serializer):
    userid = serializers.CharField(required=True)
    slotinfoid = serializers.CharField(required=True)
    coordinate_type = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    type = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    slotdate = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    class Meta:
        fields = '__all__'


class NewAssignOrdertoVehicleSerializer(serializers.Serializer):
    # ordersdeliveryid = serializers.CharField(required=True)
    assignorderlist = serializers.CharField(required=True)
    type = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    slotid = serializers.CharField(required=False ,allow_blank=True, allow_null=True)
    userid= serializers.CharField(required=False ,allow_blank=True, allow_null=True)
    class Meta:
        fields = '__all__'

class is_vehicle_free_serializers(serializers.Serializer):
    vehicle_id = serializers.CharField(required = True)
    type = serializers.CharField(required = True)


class warehousebrancheslistSerializer(serializers.Serializer):
    warehouse_branch_type = serializers.CharField(required=True)
    userid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'

class publish_order_Serializer(serializers.Serializer):
    vehicles = serializers.CharField(required=True)
    userid = serializers.CharField(required=True)
    slotid = serializers.CharField(required=True)

class GetTodayInvoicesLengthSerializer(serializers.Serializer):
    userid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'
