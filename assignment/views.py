from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from .serialiers import *
# Create your views here.


class ItemsView(APIView):
    def post(self, request):
        try:
            serializer = AddItemsSerializer(data=request.data)
            print(request.data)
            if serializer.is_valid():
                itemsinfo = Items.objects.create(
                    item_name=serializer.validated_data['item_name'],
                    item_quantity=serializer.validated_data.get(
                        'item_quantity'),
                    item_unit=serializer.validated_data.get('item_unit'),
                    item_weight=serializer.validated_data.get('item_weight'),
                )
                itemsinfo.save()
                if itemsinfo:
                    json_data = {
                        'status_code': 201,
                        'status': 'Success',
                        'vechicleinfoid': itemsinfo.id,
                        'message': 'Item Created'
                    }
                    return Response(json_data, status.HTTP_201_CREATED)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'data': 'item not created',
                        'message': 'item not created'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        try:
            ItemsOBJ = Items.objects.all()
            items = [{"id": item.id,
                      "item_name": item.item_name,
                      "item_quantity": item.item_quantity,
                      "item_unit": item.item_unit,
                      "item_weight": item.item_weight
                      }for item in ItemsOBJ]
            json_data = {
                'status_code': 200,
                'status': 'Success',
                'data': items,
                'message': 'Items found'
            }
            return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class Item(APIView):
    def get(self, request, id):
        try:
            Items_objs = Items.objects.filter(id=id)
            if Items_objs:
                Items_obj = Items.objects.get(id=id)
                Items_dict = {
                    'item_name': Items_obj.item_name,
                    'item_quantity': Items_obj.item_quantity,
                    'item_unit': Items_obj.item_unit,
                    'item_weight': Items_obj.item_weight,
                }

                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'data': Items_dict,
                    'message': 'Item found'
                }
                return Response(json_data, status.HTTP_200_OK)
            else:
                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'message': 'Item not found'
                }
                return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request, id):
        try:
            serializer = EditItemsSerializer(data=request.data)
            if serializer.is_valid():

                items = Items.objects.filter(id=id)
                if items:
                    items.update(
                        item_name=serializer.validated_data.get(
                            'item_name', ''),
                        item_quantity=serializer.validated_data.get(
                            'item_quantity', ''),
                        item_unit=serializer.validated_data.get(
                            'item_unit', ''),
                        item_weight=serializer.validated_data.get(
                            'item_weight', ''))
                    print("=========get data==", items)

                    json_data = {
                        'status_code': 205,
                        'status': 'Success',
                        'vehicleinfoid': 'Item data update',
                        'message': 'Item data changed successfully'
                    }
                    return Response(json_data, status.HTTP_205_RESET_CONTENT)
                else:
                    json_data = {
                        'status_code': 200,
                        'status': 'Success',
                        'message': 'Data not updated'
                    }
                    return Response(json_data, status.HTTP_200_OK)
            else:
                print("I am api called-------")
                json_data = {
                    'status_code': 300,
                    'status': 'Failed',
                    'error': serializer.errors,
                    'remark': 'Serializer error'
                }
                return Response(json_data, status.HTTP_300_MULTIPLE_CHOICES)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(slef, requrest, id):
        try:
            Items_objs = Items.objects.filter(id=id)
            if Items_objs:
                Items_obj = Items.objects.get(id=id)
                Items_obj.delete()
                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'message': 'Item deleted Successfully'
                }
            else:
                json_data = {
                    'status_code': 200,
                    'status': 'Success',
                    'message': 'Item Not Found'
                }
            return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)


class Units(APIView):
    def get(self, request):
        try:
            unitsObj = [
                {"name": "g"},
                {"name": "kg"},
                {"name": "pkt"},
                {"name": "piece"},
                {"name": "l"},
                {"name": "ml"},
            ]
            json_data = {
                'status_code': 200,
                'status': 'Success',
                'data': unitsObj,
                'message': 'Units Found'
            }
            return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': f'{err}',
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
