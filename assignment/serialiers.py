
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

from .models import *


class AddItemsSerializer(serializers.Serializer):
    item_name = serializers.CharField(required=True)
    item_quantity = serializers.IntegerField(required=True)
    item_unit = serializers.IntegerField(required=True)
    item_weight = serializers.FloatField(required=True)

    class Meta:
        fields = '__all__'



class EditItemsSerializer(serializers.Serializer):
    item_name = serializers.CharField(required=True)
    item_quantity = serializers.IntegerField(required=True)
    item_unit = serializers.IntegerField(required=True)
    item_weight = serializers.FloatField(required=True)

    class Meta:
        fields = '__all__'